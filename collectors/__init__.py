"""Packaging shim.

The collectors are plain shell/PowerShell scripts; this file exists only so the
directory ships inside the wheel as ``endpointsweep.collectors`` and
``endpointsweep scan`` works from a plain ``pip install``. Nothing imports it.
"""
