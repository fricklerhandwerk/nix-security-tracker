from django.test import LiveServerTestCase
from playwright.sync_api import expect
import pytest





def test_visual(live_server, page, visual_compare):
    page.goto(live_server.url)
    visual_compare(page.screenshot(full_page=True), "homepage")
    visual_compare(page.screenshot(full_page=True), "homepage")

