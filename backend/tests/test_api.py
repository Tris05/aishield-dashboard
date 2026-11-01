import os, unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
from app import main as main_module

class FakeResult:
    def __init__(self, inserted_id=None): self.inserted_id=inserted_id
class FakeCollection:
    def __init__(self): self.docs=[]
    def find_one(self, query):
        for d in self.docs:
            if all(d.get(k)==v for k,v in query.items()): return d.copy()
        return None
    def insert_one(self, doc): self.docs.append(doc.copy()); return FakeResult()
    def update_one(self, query, update):
        for d in self.docs:
            if all(d.get(k)==v for k,v in query.items()): d.update(update.get("$set",{})); break
    def find(self, query): return [d.copy() for d in self.docs if all(d.get(k)==v for k,v in query.items())]
    def create_index(self, *args, **kwargs): return "fake-index"
class FakeDB:
    def __init__(self): self.projects=FakeCollection();self.scans=FakeCollection();self.remediation_sessions=FakeCollection();self.fix_proposals=FakeCollection()

class ApiSmokeTests(unittest.TestCase):
    def setUp(self):
        self.db=FakeDB(); self.client=TestClient(app)
        self.patcher=patch.object(main_module,"get_database",return_value=self.db); self.patcher.start()
        self.env=patch("app.config.settings.ingest_token","test-ingest-token"); self.env.start()
        self.pub=patch("app.config.settings.public_base_url","http://localhost:3000"); self.pub.start()
    def tearDown(self): self.patcher.stop(); self.env.stop(); self.pub.stop(); self.client.close()
    def test_health(self): self.assertEqual(self.client.get("/api/v1/health").status_code,200)
    def test_upload_and_public_fetch(self):
        payload={"repository_url":"https://github.com/acme/demo","branch":"main","commit_sha":"abc123","scan_status":"completed","report":{"finding_count":1,"findings":[{"id":"f1","title":"Demo finding","severity":"high","category":"sast","path":"src/app.py","line":4}]}}
        r=self.client.post("/api/v1/scans/upload",json=payload,headers={"Authorization":"Bearer test-ingest-token"})
        self.assertEqual(r.status_code,200,r.text); data=r.json(); self.assertTrue(data["dashboard_url"].startswith("http://localhost:3000/s/"))
        token=data["dashboard_url"].rsplit("/",1)[-1]
        view=self.client.get(f"/api/v1/public/scans/{token}")
        self.assertEqual(view.status_code,200,view.text); self.assertEqual(view.json()["report"]["finding_count"],1)
    def test_consent_is_required_before_creating_remediation_session(self):
        payload={"repository_url":"https://github.com/acme/consent-demo","branch":"main","commit_sha":"abc1234","report":{"findings":[{"id":"finding-1","title":"Unsafe code","severity":"high","category":"sast","path":"src/app.py","line":4}]}}
        uploaded=self.client.post("/api/v1/scans/upload",json=payload,headers={"Authorization":"Bearer test-ingest-token"})
        token=uploaded.json()["dashboard_url"].rsplit("/",1)[-1]
        denied=self.client.post(f"/api/v1/public/scans/{token}/remediation/sessions",json={"consent":False})
        self.assertEqual(denied.status_code,403)
        allowed=self.client.post(f"/api/v1/public/scans/{token}/remediation/sessions",json={"consent":True,"finding_ids":["finding-1"]})
        self.assertEqual(allowed.status_code,200,allowed.text)
        self.assertEqual(allowed.json()["finding_count"],1)

    def test_repeated_uploads_get_new_scan_ids_and_keep_prior_documents(self):
        payload={"repository_url":"https://github.com/acme/repeated-demo","branch":"main","commit_sha":"abc1234","report":{"findings":[]}}
        first=self.client.post("/api/v1/scans/upload",json=payload,headers={"Authorization":"Bearer test-ingest-token"}).json()
        second=self.client.post("/api/v1/scans/upload",json=payload,headers={"Authorization":"Bearer test-ingest-token"}).json()
        self.assertNotEqual(first["scan_id"],second["scan_id"])
        self.assertEqual(len(self.db.scans.docs),2)
        self.assertEqual(self.db.projects.docs[0]["latest_scan_id"],second["scan_id"])

    def test_upload_rejects_report_without_findings_array(self):
        r=self.client.post("/api/v1/scans/upload",json={"repository_url":"https://github.com/acme/demo","report":{}},headers={"Authorization":"Bearer test-ingest-token"})
        self.assertEqual(r.status_code,422)

    def test_upload_requires_ingest_token(self):
        r=self.client.post("/api/v1/scans/upload",json={"repository_url":"https://github.com/acme/demo","report":{"findings":[]}})
        self.assertEqual(r.status_code,401)
    def test_repository_url_validation(self):
        r=self.client.post("/api/v1/scans/upload",json={"repository_url":"https://example.com/acme/demo","report":{"findings":[]}},headers={"Authorization":"Bearer test-ingest-token"})
        self.assertEqual(r.status_code,400)

if __name__=="__main__": unittest.main()
