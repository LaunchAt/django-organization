# -*- coding: utf-8 -*-
# flake8: noqa

from .example.manage import setup

setup()

from django.test import TestCase

from organization.services import OrganizationService
from tests.example.models import (
    ExampleInvitation,
    ExampleMember,
    ExampleOrganization,
    ExampleUser,
)


class ServiceTestCase(TestCase):
    @classmethod
    def setup_class(cls):
        pass

    @classmethod
    def teardown_class(cls):
        pass

    def setup_method(self, method):
        pass

    def teardown_method(self, method):
        pass

    def test_service(self):
        OrganizationService(
            invitation_class=ExampleInvitation,
            member_class=ExampleMember,
            organization_class=ExampleOrganization,
            user_class=ExampleUser,
        )
