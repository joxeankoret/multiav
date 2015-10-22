import os
import sys
import json
import time

import web
from hashlib import md5, sha1, sha256
from multiav.core import CMultiAV, AV_SPEED_ULTRA

urls = (
    '/', 'index',
    '/upload', 'upload',
    '/api/upload', 'api_upload',
    '/api/upload_fast', 'api_upload_fast',
    '/api/search', 'api_search',
    '/about', 'about',
    '/last', 'last',
    '/search', 'search',
)

app = web.application(urls, globals())
ROOT_PATH = os.path.dirname(__file__)
CURRENT_PATH = os.getcwd()
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')

if not os.path.isdir(os.path.join(CURRENT_PATH, 'static')):
    raise Exception('runserver.py must be run in the directory {0}'.format(ROOT_PATH))


# -----------------------------------------------------------------------
class CDbSamples:
  def __init__(self):
    self.db = web.database(dbn='sqlite', db='multiav.db')
    self.db.printing = False
    self.create_schema()

  def create_schema(self):
    self.db.query("""create table if not exists samples(
                    id integer not null primary key autoincrement,
                    name text,
                    md5 text unique,
                    sha1 text unique,
                    sha256 text unique,
                    report text,
                    infected integer,
                    date text)""")

  def insert_sample(self, name, buf, report):
    infected = 0
    for ret in report:
      if report[ret] != {}:
        infected = 1
        break

    md5_hash = md5(buf).hexdigest()
    sha1_hash = sha1(buf).hexdigest()
    sha256_hash = sha256(buf).hexdigest()

    with self.db.transaction():
      try:
        self.db.insert('samples', md5=md5_hash, sha1=sha1_hash, sha256=sha256_hash, \
                       report=json.dumps(report), infected=infected, date=time.asctime(),\
                       name=name)
        print "Sample inserted", sha1_hash
      except:
        print "Error:", sys.exc_info()[1], md5_hash, sha1_hash, sha256_hash

  def search_sample(self, file_hash):
    where = "md5=$val or sha1=$val or sha256=$val"
    rows = self.db.select('samples', vars={"val":file_hash}, where=where)
    return rows

  def search_samples(self, query):
    where = "md5=$val or sha1=$val or sha256=$val or report like $val or name like $val"
    rows = self.db.select('samples', vars={"val":query}, where=where)
    return rows

  def last_samples(self):
    where = "infected=1"
    rows = self.db.select('samples', where=where, order="date desc", limit=20)
    return rows


# -----------------------------------------------------------------------
class last:
  def GET(self):
    db = CDbSamples()
    rows = db.last_samples()
    l = []
    for row in rows:
      l.append([row.name, json.loads(row.report), row.md5, row.sha1, row.sha256, row.date])

    render = web.template.render(TEMPLATE_PATH)
    return render.search_results(l)


# -----------------------------------------------------------------------
class search:
  def GET(self):
    render = web.template.render(TEMPLATE_PATH)
    return render.search()

  def POST(self):
    render = web.template.render(TEMPLATE_PATH)
    i = web.input(q="")
    if i["q"] == "":
      return render.search()

    db = CDbSamples()
    rows = db.search_samples(i["q"])
    l = []
    for row in rows:
      l.append([row.name, json.loads(row.report), row.md5, row.sha1, row.sha256, row.date])

    if len(l) == 0:
      return render.error("No match")
    return render.search_results(l)


# -----------------------------------------------------------------------
class index:
  def GET(self):
    render = web.template.render(TEMPLATE_PATH)
    return render.index()


# -----------------------------------------------------------------------
class about:
  def GET(self):
    render = web.template.render(TEMPLATE_PATH)
    return render.about()


# -----------------------------------------------------------------------
class api_search:
  def GET(self):
    return self.POST()

  def POST(self):
    i = web.input(file_hash="")
    if i["file_hash"] == "":
      return '{"error": "No file uploaded or invalid file."}'

    db_api = CDbSamples()
    ret = db_api.search_sample(i["file_hash"])
    for row in ret:
      return json.dumps(row)
    return '{"error": "Not found."}'


# -----------------------------------------------------------------------
class api_upload:
  def POST(self):
    i = web.input(file_upload={})
    if "file_upload" not in i or i["file_upload"] is None or i["file_upload"] == "":
      return '{"error": "No file uploaded or invalid file."}'

    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    # Scan the file
    av = CMultiAV()
    report = av.scan_buffer(buf)

    db_api = CDbSamples()
    db_api.insert_sample(filename, buf, report)
    return json.dumps(report)


# -----------------------------------------------------------------------
class api_upload_fast:
  def POST(self):
    i = web.input(file_upload={}, speed=AV_SPEED_ULTRA)
    if i["file_upload"] is None or i["file_upload"] == "":
      return "{'error':'No file uploaded or invalid file.'}"

    speed = int(i["speed"])
    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    # Scan the file
    av = CMultiAV()
    report = av.scan_buffer(buf, speed)

    db_api = CDbSamples()
    db_api.insert_sample(filename, buf, report)

    return json.dumps(report)


# -----------------------------------------------------------------------
class upload:
  def POST(self):
    i = web.input(file_upload={})
    if i["file_upload"] is None or i["file_upload"] == "":
      return render.error("No file uploaded or invalid file.")

    buf = i["file_upload"].value
    filename = i["file_upload"].filename

    # Scan the file
    av = CMultiAV()
    ret = av.scan_buffer(buf)

    # Calculate the hashes
    hashes = []
    hashes.append(md5(buf).hexdigest())
    hashes.append(sha1(buf).hexdigest())
    hashes.append(sha256(buf).hexdigest())

    # Save the sample
    db_api = CDbSamples()
    db_api.insert_sample(filename, buf, ret)

    # And show the results
    render = web.template.render(TEMPLATE_PATH)
    return render.results(ret, filename, hashes)
