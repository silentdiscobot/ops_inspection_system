# -*- coding: utf-8 -*-
"""Gunicorn entry point used by the production container."""

from app import app, initialize_runtime


initialize_runtime()
application = app
