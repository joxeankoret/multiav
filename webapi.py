#!/usr/bin/python

import web

urls = (
    '/', 'index',
    '/upload', 'upload',
    '/api/upload', 'api_upload',
    '/about', 'about'
)

app = web.application(urls, globals())

from hashlib import md5, sha1, sha256
from multiav import CMultiAV, AV_SPEED_ULTRA

#-----------------------------------------------------------------------
class index:
  def GET(self):
    render = web.template.render('templates')
    return render.index()

#-----------------------------------------------------------------------
class about:
  def GET(self):
    render = web.template.render('templates')
    return render.about()

#-----------------------------------------------------------------------
class upload_api:
  def POST(self):
    i = web.input(file_upload={})
    if i["file_upload"] is None or i["file_upload"] == "":
      return "{'error':'No file uploaded or invalid file.'}"

    buf = i["file_upload"].value
    filename = i["file_upload"].filename
    
    # Scan the file
    av = CMultiAV()
    return av.scan_buffer(buf)

#-----------------------------------------------------------------------
class upload:
  def POST(self):
    i = web.input(file_upload={})
    if i["file_upload"] is None or i["file_upload"] == "":
      return render.error("No file uploaded or invalid file.")

    buf = i["file_upload"].value
    filename = i["file_upload"].filename
    
    # Scan the file
    av = CMultiAV()
    ret = av.scan_buffer(buf, AV_SPEED_ULTRA)
    
    # Calculate the hashes
    hashes = []
    hashes.append(md5(buf).hexdigest())
    hashes.append(sha1(buf).hexdigest())
    hashes.append(sha256(buf).hexdigest())

    # And show the results
    render = web.template.render('templates')
    return render.results(ret, filename, hashes)

if __name__ == "__main__":
    app.run()
