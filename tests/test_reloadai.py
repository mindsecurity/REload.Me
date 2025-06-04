# test_reloadai.py
import unittest
import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

class TestREloadAI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_url = "http://localhost:8000"
        cls.api_key = os.getenv("TEST_API_KEY")
        cls.headers = {"Authorization": f"Bearer {cls.api_key}"}
        
        # Wait for services to be ready
        max_retries = 10
        for i in range(max_retries):
            try:
                response = requests.get(f"{cls.base_url}/health")
                if response.status_code == 200:
                    break
            except:
                if i == max_retries - 1:
                    raise Exception("API service not available")
                time.sleep(3)
    
    def test_health_check(self):
        """Test API health check endpoint"""
        response = requests.get(f"{self.base_url}/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")
    
    def test_authentication(self):
        """Test API authentication"""
        # Without API key
        response = requests.get(f"{self.base_url}/api/v1/usage/stats")
        self.assertEqual(response.status_code, 403)
        
        # With valid API key
        response = requests.get(f"{self.base_url}/api/v1/usage/stats", headers=self.headers)
        self.assertEqual(response.status_code, 200)
    
    def test_binary_analysis(self):
        """Test binary analysis endpoint"""
        # Create a simple test binary
        test_binary_content = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
        
        with open("test_binary", "wb") as f:
            f.write(test_binary_content)
        
        # Upload for analysis
        with open("test_binary", "rb") as f:
            files = {"file": ("test_binary", f, "application/octet-stream")}
            response = requests.post(
                f"{self.base_url}/api/v1/analyze",
                files=files,
                headers=self.headers
            )
        
        self.assertEqual(response.status_code, 200)
        analysis_id = response.json()["analysis_id"]
        
        # Poll for results
        max_retries = 30
        for i in range(max_retries):
            result_response = requests.get(
                f"{self.base_url}/api/v1/analysis/{analysis_id}",
                headers=self.headers
            )
            
            if result_response.status_code == 200:
                result = result_response.json()
                if result["status"] == "completed":
                    self.assertIn("file_info", result)
                    self.assertIn("protections", result)
                    break
            
            time.sleep(2)
        
        # Clean up
        os.remove("test_binary")
    
    def test_usage_stats(self):
        """Test usage statistics endpoint"""
        response = requests.get(f"{self.base_url}/api/v1/usage/stats", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        
        stats = response.json()
        self.assertIn("total_analyses", stats)
        self.assertIn("success_rate", stats)
    
    def test_marketplace_browse(self):
        """Test marketplace browsing endpoint"""
        response = requests.get(f"{self.base_url}/api/v1/marketplace/exploits")
        self.assertEqual(response.status_code, 200)
        
        exploits = response.json()
        if len(exploits) > 0:
            self.assertIn("title", exploits[0])
            self.assertIn("price", exploits[0])

if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
