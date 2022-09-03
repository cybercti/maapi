"""
Helper functions to render the various document types.
"""
from json import dumps
from typing import Dict

def _render_preview_report(document):
    threat_detail = document.get("threat_detail", "[[[ Empty threat_detail ]]]").replace('\n', ' -> ')[:50]
    # report_type publish_date report_id title     threat_detail tags
    return f'|  ID: {document["report_id"]:14} Title: {document["title"]:25}  |\n|  Type: {document["report_type"]:43} Published: {document["publish_date"]:90} |\n|  Body: {threat_detail:145} |'

def _render_preview(doc_type:str, document:Dict, max_width:int=1000):
    if doc_type == "report":
        return _render_preview_report(document)[:max_width]
    return dumps(document)[:max_width]
