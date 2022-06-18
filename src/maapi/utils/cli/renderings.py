"""
Helper functions to render the various document types.
"""
from json import dumps

def _render_preview_message(document):
    body = document.get("body", "[[[ Empty body ]]]").replace('\n', ' -> ')
    return f'From: {document["channel"]["name"]:20} Body: {body:50}'

def _render_preview_paste(document):
    if document.get("title", ""):
        title = document.get("title", "[[[ Empty Title ]]]")[:20]
        body = document.get("body", "[[[ Empty body ]]]").replace('\n', ' -> ')
        return f'Title: {title:20}  Body: {body:50}'

    message = document.get("body", "[[[ Empty body ]]]").replace('\n', ' -> ')
    return f'From: {document["channel"]["name"]:20} Body: {message:50}'



def _render_preview(document, max_width:int=50):

    if document["__type"] == "message":
        return _render_preview_message(document)
    if document["__type"] == "paste":
        return _render_preview_paste(document)
    return dumps(document)[:max_width]
