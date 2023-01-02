import os
import sys

import django
from django.core.management import execute_from_command_line


def setup():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.example.settings')
    django.setup()


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.example.settings')
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
