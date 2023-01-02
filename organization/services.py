import datetime
import logging
from typing import Type, TypeVar, Union
from uuid import UUID

import jsonschema
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Model as DjangoModel
from django.db.models.query import QuerySet as DjangoQuerySet
from django.utils.timezone import now

from .models import Invitation as BaseInvitation
from .models import InvitationStatus
from .models import Member as BaseMember
from .models import Organization as BaseOrganization
from .models import PermissionLevel

logger = logging.getLogger(__name__)


# Types

User = TypeVar('User', bound=DjangoModel)


# schema

PERMISSIONS_POLICY_SCHEMA = {
    'type': 'object',
    'properties': {
        'version': {'type': 'number'},
        'statement': {
            'type': 'object',
            'additionalProperties': {
                'anyOf': [
                    {'type': 'string'},
                    {'type': 'number'},
                ],
            },
        },
    },
    'required': ['version'],
}


# Service


class OrganizationService:
    def __init__(
        self: 'OrganizationService',
        *,
        invitation_class: Union[Type[BaseInvitation], None] = None,
        member_class: Union[Type[BaseMember], None] = None,
        organization_class: Union[Type[BaseOrganization], None] = None,
        user_class: Union[Type[User], None] = None,
    ) -> None:
        if (
            invitation_class is None
            or member_class is None
            or organization_class is None
            or user_class is None
            or not issubclass(invitation_class, BaseInvitation)
            or not issubclass(member_class, BaseMember)
            or not issubclass(organization_class, BaseOrganization)
            or not issubclass(user_class, DjangoModel)
        ):
            raise ValidationError

        self._invitation_model = invitation_class
        self._member_model = member_class
        self._organization_model = organization_class
        self._user_model = user_class

    def _validate_permissions_policy(
        self: 'OrganizationService',
        *,
        permissions_policy: Union[dict, None] = None,
    ) -> None:
        if permissions_policy is None:
            raise ValidationError

        try:
            jsonschema.validate(
                instance=permissions_policy,
                schema=PERMISSIONS_POLICY_SCHEMA,
            )

        except jsonschema.ValidationError:
            raise ValidationError

    def _validate_instances(
        self: 'OrganizationService',
        *,
        invitation: Union[BaseInvitation, None] = None,
        member: Union[BaseMember, None] = None,
        organization: Union[BaseOrganization, None] = None,
        user: Union[User, None] = None,
        uuid: Union[str, UUID, None] = None,
    ) -> None:
        if invitation is not None:
            if not isinstance(invitation, self._invitation_model):
                raise ValidationError

        if member is not None:
            if not isinstance(member, self._member_model):
                raise ValidationError

        if organization is not None:
            if not isinstance(organization, self._organization_model):
                raise ValidationError

        if user is not None:
            if not isinstance(user, self._user_model):
                raise ValidationError

        if uuid is not None:
            if not isinstance(uuid, (str, UUID)):
                raise ValidationError

            if isinstance(uuid, str):
                try:
                    UUID(uuid)

                except ValueError:
                    raise ValidationError

    def _check_user_permission(
        self: 'OrganizationService',
        *,
        action: Union[str, None] = None,
        organization: Union[BaseOrganization, None] = None,
        user: Union[User, None] = None,
    ) -> bool:
        if not action or organization is None or user is None:
            raise ValidationError

        permissions_policy = organization.permissions_policy or {'version': 0}
        self._validate_permissions_policy(permissions_policy=permissions_policy)
        version = permissions_policy.get('version', 0)
        kwargs = {'user_id': user.id, 'organization_id': organization.id}

        if version == 0:
            kwargs[
                'permission_level__gte'
            ] = PermissionLevel.OWNER.value  # type: ignore
            queryset = self._member_model.objects.filter(**kwargs)

            if not queryset.filter(deleted_at__isnull=True).exists():
                raise PermissionDenied

        elif version == 1:
            statement = permissions_policy.get('statement', {})

            if action in statement:
                permission_level = statement.get(action)

                if permission_level != 0:
                    kwargs['permission_level__gte'] = permission_level
                    queryset = self._member_model.objects.filter(**kwargs)

                    if not queryset.filter(deleted_at__isnull=True).exists():
                        raise PermissionDenied

        raise PermissionDenied

    def get_organization_set(
        self: 'OrganizationService',
    ) -> DjangoQuerySet[BaseOrganization]:
        queryset = self._organization_model.objects.all()
        queryset = queryset.select_related('owner', 'super_organization')
        queryset = queryset.prefetch_related(
            'member_set',
            'invitation_set',
            'sub_organization_set',
        )
        return queryset

    def get_sub_organization_set(
        self: 'OrganizationService',
        *,
        organization: Union[BaseOrganization, None] = None,
        request_user: Union[User, None] = None,
    ) -> DjangoQuerySet[BaseOrganization]:
        if organization is None or request_user is None:
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user)
        self._check_user_permission(
            action='get_sub_organization_set',
            organization=organization,
            user=request_user,
        )
        queryset = organization.sub_organization_set.all()
        queryset = queryset.select_related('owner', 'super_organization')
        queryset = queryset.prefetch_related(
            'member_set',
            'invitation_set',
            'sub_organization_set',
        )
        return queryset

    def get_organization(
        self: 'OrganizationService',
        *,
        id: Union[UUID, None] = None,
        request_user: Union[User, None] = None,
    ) -> Union[BaseOrganization, None]:
        if id is None or request_user is None:
            raise ValidationError

        self._validate_instances(user=request_user, uuid=id)
        queryset = self._organization_model.objects.all()
        queryset = queryset.filter(id=id)
        queryset = queryset.select_related('owner', 'super_organization')
        queryset = queryset.prefetch_related(
            'member_set',
            'invitation_set',
            'sub_organization_set',
        )

        try:
            organization = queryset.get()
            return organization

        except self._organization_model.DoesNotExist:
            return None

    def update_organization_policy(
        self: 'OrganizationService',
        *,
        permissions_policy: Union[dict, None] = None,
        organization: Union[BaseOrganization, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseOrganization:
        if organization is None or request_user is None:
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user)
        self._check_user_permission(
            action='update_organization_policy',
            organization=organization,
            user=request_user,
        )
        self._validate_permissions_policy(permissions_policy=permissions_policy)
        organization.permissions_policy = permissions_policy
        organization.save(update_fields=['permissions_policy'])
        return organization

    def create_organization(
        self: 'OrganizationService',
        *,
        request_user: Union[User, None] = None,
    ) -> BaseOrganization:
        if request_user is None:
            raise ValidationError

        self._validate_instances(user=request_user)
        organization = self._organization_model.objects.create(owner_id=request_user.id)
        return organization

    def create_sub_organization(
        self: 'OrganizationService',
        *,
        organization: Union[BaseOrganization, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseOrganization:
        if organization is None or request_user is None:
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user)
        self._check_user_permission(
            action='create_sub_organization',
            organization=organization,
            user=request_user,
        )
        kwargs = {'owner_id': request_user.id, 'super_organization_id': organization.id}
        sub_organization = self._organization_model.objects.create(**kwargs)
        return sub_organization

    def delete_organization(
        self: 'OrganizationService',
        *,
        organization: Union[BaseOrganization, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseOrganization:
        if organization is None or request_user is None:
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user)
        self._check_user_permission(
            action='delete_organization',
            organization=organization,
            user=request_user,
        )

        organization.delete()
        return organization

    def get_invitation_set(
        self: 'OrganizationService',
        *,
        organization: Union[BaseOrganization, None] = None,
        request_user: Union[User, None] = None,
    ) -> DjangoQuerySet[BaseInvitation]:
        if organization is None or request_user is None:
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user)
        self._check_user_permission(
            action='get_invitation_set',
            organization=organization,
            user=request_user,
        )
        queryset = organization.invitation_set.all()
        queryset = queryset.filter(
            status=InvitationStatus.PENDING.value,  # type: ignore
        )
        queryset = queryset.select_related('inviter', 'member', 'organization')
        return queryset

    def create_invitation(
        self: 'OrganizationService',
        *,
        email: Union[str, None] = None,
        expires_at: Union[datetime.date, None] = None,
        organization: Union[BaseOrganization, None] = None,
        permission_level: Union[int, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseInvitation:
        if (
            email is None
            or expires_at is None
            or organization is None
            or request_user is None
        ):
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user)
        self._check_user_permission(
            action='create_invitation',
            organization=organization,
            user=request_user,
        )
        kwargs = {
            'email': email,
            'expires_at': expires_at,
            'inviter': request_user.id,
            'organization_id': organization.id,
        }

        if permission_level:
            kwargs['permission_level'] = permission_level

        invitaiton = self._invitation_model.objects.create(**kwargs)
        return invitaiton

    def update_invitation_permission(
        self: 'OrganizationService',
        *,
        invitation: Union[BaseInvitation, None] = None,
        permission_level: Union[int, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseInvitation:
        if (
            invitation is None
            or request_user is None
            or not isinstance(permission_level, int)
        ):
            raise ValidationError

        self._validate_instances(invitation=invitation, user=request_user)

        if invitation.status != InvitationStatus.PENDING.value:  # type: ignore
            raise ValidationError

        self._check_user_permission(
            action='update_invitation_permission',
            organization=invitation.organization,
            user=request_user,
        )

        invitation.permission_level = permission_level
        invitation.save(update_fields=['permission_level'])
        return invitation

    def cancel_invitation(
        self: 'OrganizationService',
        *,
        invitation: Union[BaseInvitation, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseInvitation:
        if invitation is None or request_user is None:
            raise ValidationError

        self._validate_instances(invitation=invitation, user=request_user)

        if invitation.status != InvitationStatus.PENDING.value:  # type: ignore
            raise ValidationError

        self._check_user_permission(
            action='cancel_invitation',
            organization=invitation.organization,
            user=request_user,
        )

        invitation.status = InvitationStatus.CANCELED.value  # type: ignore
        invitation.save(update_fields=['status'])
        return invitation

    def accept_invitation(
        self: 'OrganizationService',
        *,
        invitation: Union[BaseInvitation, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseMember:
        if invitation is None or request_user is None:
            raise ValidationError

        self._validate_instances(invitation=invitation, user=request_user)

        if invitation.status != InvitationStatus.PENDING.value:  # type: ignore
            raise ValidationError

        invitation.status = InvitationStatus.ACCEPTED.value  # type: ignore
        invitation.save(update_fields=['status'])
        kwargs = {
            'invitation_id': invitation.id,
            'organization_id': invitation.organization.id,
            'permission_level': invitation.permission_level,
            'user_id': request_user.id,
        }
        member = self._member_model.objects.create(**kwargs)
        return member

    def decline_invitation(
        self: 'OrganizationService',
        *,
        invitation: Union[BaseInvitation, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseInvitation:
        if invitation is None or request_user is None:
            raise ValidationError

        self._validate_instances(invitation=invitation, user=request_user)

        if invitation.status != InvitationStatus.PENDING.value:  # type: ignore
            raise ValidationError

        invitation.status = InvitationStatus.DECLINED.value  # type: ignore
        invitation.save(update_fields=['status'])
        return invitation

    def revoke_expired_invitation_set(
        self: 'OrganizationService',
    ) -> DjangoQuerySet[BaseInvitation]:
        queryset = self._invitation_model.objects.all()
        queryset = queryset.filter(
            status=InvitationStatus.PENDING.value,  # type: ignore
        )
        queryset = queryset.filter(expires_at__lt=now())
        queryset.update(status=InvitationStatus.EXPIRED.value)  # type: ignore
        return queryset

    def get_member_set(
        self: 'OrganizationService',
        *,
        organization: Union[BaseOrganization, None] = None,
        request_user: Union[User, None] = None,
    ) -> DjangoQuerySet[BaseMember]:
        if organization is None or request_user is None:
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user)
        self._check_user_permission(
            action='get_member_set',
            organization=organization,
            user=request_user,
        )
        queryset = organization.member_set.all()
        queryset = queryset.select_related('invitation', 'organization', 'user')
        return queryset

    def get_member(
        self: 'OrganizationService',
        *,
        id: Union[UUID, None] = None,
        organization: Union[BaseOrganization, None] = None,
        request_user: Union[User, None] = None,
    ) -> Union[BaseMember, None]:
        if id is None or organization is None or request_user is None:
            raise ValidationError

        self._validate_instances(organization=organization, user=request_user, uuid=id)
        self._check_user_permission(
            action='get_member',
            organization=organization,
            user=request_user,
        )
        queryset = organization.member_set.all()
        queryset = queryset.filter(id=id)
        queryset = queryset.select_related('invitation', 'organization', 'user')

        try:
            member = queryset.get()
            return member

        except self._member_model.DoesNotExist:
            return None

    def update_member_permission(
        self: 'OrganizationService',
        *,
        member: Union[BaseMember, None] = None,
        new_owner: Union[User, None] = None,
        permission_level: Union[int, None] = None,
        request_user: Union[User, None] = None,
    ) -> BaseMember:
        if (
            member is None
            or permission_level is None
            or request_user is None
            or not isinstance(permission_level, int)
        ):
            raise ValidationError

        self._validate_instances(member=member, user=request_user)

        if member.permission_level == permission_level:
            return member

        self._check_user_permission(
            action='update_member_permission',
            organization=member.organization,
            user=request_user,
        )

        if (
            member.permission_level == PermissionLevel.OWNER.value  # type: ignore
            and member.user_id == member.organization.owner_id
        ):
            if new_owner is None:
                raise ValidationError

            self._validate_instances(user=new_owner)
            queryset = member.organization.member_set.all()
            queryset = queryset.filter(user_id=new_owner.id)
            queryset = queryset.filter(
                permission_level=PermissionLevel.OWNER.value,  # type: ignore
            )

            if queryset.exists():
                member.organization.owner = new_owner
                member.organization.save(update_fields=['owner'])

            else:
                raise ValidationError

        member.permission_level = permission_level
        member.save(update_fields=['permission_level'])
        return member
