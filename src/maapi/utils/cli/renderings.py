"""
Helper functions to render the various document types.
"""
from json import dumps

def _render_preview_message(document):
    body = document.get("body", "[[[ Empty body ]]]").replace('\n', ' -> ')
    return f'From: {document["channel"]["name"]:20} Body: {body:50}'

def _render_preview_paste(document):
    title = document.get("title", "[[[ Empty Title ]]]")[:20]
    body = document.get("body", "[[[ Empty body ]]]").replace('\n', ' -> ')
    return f'Title: {title:20}  Body: {body:50}'

def _render_preview_web_content_publish(document):
    title = document.get("title", "[[[ Empty Title ]]]")[:20]
    text = document.get("text", "[[[ Empty text ]]]").replace('\n', ' -> ')
    return f'Title: {title:20}  Text: {text}'



def _render_preview(document, max_width:int=100):
    if document["__type"] == "message":
        return _render_preview_message(document)[:max_width]
    if document["__type"] == "paste":
        return _render_preview_paste(document)[:max_width]
    if document["__type"] == "web_content_publish":
        return _render_preview_web_content_publish(document)[:max_width]
    return dumps(document)[:max_width]
