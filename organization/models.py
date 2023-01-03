from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.base.models import BaseModel

USER_MODEL = getattr(settings, 'ORGANIZATION_USER_MODEL', settings.AUTH_USER_MODEL)


class PermissionLevel(models.IntegerChoices):
    ANONYMOUS = 0, _('anonymous')
    GUEST = 20, _('guest')
    STAFF = 40, _('staff')
    MANAGER = 60, _('manager')
    OWNER = 80, _('owner')
    ADMIN = 100, _('admin')


class InvitationStatus(models.IntegerChoices):
    PENDING = 1, _('pending')
    ACCEPTED = 2, _('accepted')
    DECLINED = 3, _('declined')
    CANCELED = 4, _('canceled')
    EXPIRED = 5, _('expired')


class Invitation(BaseModel):
    permission_level = models.PositiveIntegerField(
        _('permission level'),
        choices=PermissionLevel.choices,
        default=PermissionLevel.GUEST.value,  # type: ignore
    )
    email = models.EmailField(_('email'))
    expires_at = models.DateTimeField(_('expires date-time'))
    inviter = models.ForeignKey(
        USER_MODEL,
        on_delete=models.PROTECT,
        verbose_name=_('user who invites'),
    )
    organization = models.ForeignKey(
        'organization.Organization',
        on_delete=models.PROTECT,
        verbose_name=_('organization'),
    )
    status = models.PositiveIntegerField(
        _('status'),
        choices=InvitationStatus.choices,
        default=InvitationStatus.PENDING.value,  # type: ignore
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'email'],
                condition=models.Q(
                    status=InvitationStatus.PENDING.value,  # type: ignore
                ),
                name='unique_organization_and_email',
            ),
        ]
        ordering = ('-created_at',)
        verbose_name = _('invitation')
        verbose_name_plural = _('invitations')


class Member(BaseModel):
    permission_level = models.PositiveIntegerField(
        _('permission level'),
        choices=PermissionLevel.choices,
        default=PermissionLevel.GUEST.value,  # type: ignore
    )
    invitation = models.OneToOneField(
        'organization.Invitation',
        on_delete=models.PROTECT,
        verbose_name=_('invitation'),
        null=True,
        default=None,
    )
    organization = models.ForeignKey(
        'organization.Organization',
        on_delete=models.PROTECT,
        verbose_name=_('organization'),
    )
    user = models.ForeignKey(
        USER_MODEL,
        on_delete=models.PROTECT,
        verbose_name=_('user'),
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'user'],
                name='unique_organization_and_user',
            ),
        ]
        ordering = ('-permission_level', 'created_at')
        verbose_name = _('member')
        verbose_name_plural = _('members')


class Organization(BaseModel):
    permissions_policy = models.JSONField(
        _('permissions policy'),
        null=True,
        default=None,
    )
    level = models.PositiveIntegerField(_('level'), default=0)
    owner = models.ForeignKey(
        USER_MODEL,
        on_delete=models.PROTECT,
        verbose_name=_('owner'),
    )
    super_organization = models.ForeignKey(
        'organization.Organization',
        on_delete=models.PROTECT,
        verbose_name=_('super organization'),
        related_name='sub_organization_set',
        null=True,
        default=None,
    )

    class Meta:
        ordering = ('-created_at',)
        verbose_name = _('organization')
        verbose_name_plural = _('organizations')
