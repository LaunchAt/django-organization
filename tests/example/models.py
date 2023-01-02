from django.contrib.auth.models import User

from organization.models import Invitation, Member, Organization


class ExampleInvitation(Invitation):
    pass


class ExampleMember(Member):
    pass


class ExampleOrganization(Organization):
    pass


class ExampleUser(User):
    pass
