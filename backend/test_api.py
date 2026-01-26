"""
Test script to populate database with mock PR data
"""
import requests
import time

BASE_URL = "http://localhost:8000/api"

# Mock PR data
mock_prs = [
    {
        "repo_name": "example/secure-app",
        "pr_number": 123,
        "pr_url": "https://github.com/example/secure-app/pull/123"
    },
    {
        "repo_name": "example/api-service",
        "pr_number": 456,
        "pr_url": "https://github.com/example/api-service/pull/456"
    },
    {
        "repo_name": "example/frontend-app",
        "pr_number": 789,
        "pr_url": "https://github.com/example/frontend-app/pull/789"
    }
]

def test_health():
    """Test health endpoint"""
    response = requests.get(f"{BASE_URL}/health")
    print(f"Health check: {response.json()}")

def submit_mock_prs():
    """Submit mock PRs for analysis"""
    for pr_data in mock_prs:
        print(f"\nSubmitting PR #{pr_data['pr_number']}...")
        response = requests.post(f"{BASE_URL}/analyze", json=pr_data)
        result = response.json()
        print(f"Response: {result}")
        time.sleep(1)

def get_all_results():
    """Fetch all analysis results"""
    print("\n\nFetching all results...")
    response = requests.get(f"{BASE_URL}/results")
    results = response.json()
    print(f"\nTotal PRs: {len(results)}")
    for pr in results:
        print(f"  PR #{pr['pr_number']}: {pr['status']} - {pr['verdict']} (Risk: {pr['risk_score']})")

if __name__ == "__main__":
    print("Testing PR Analysis API\n" + "="*50)
    
    # Test health
    test_health()
    
    # Submit mock PRs
    submit_mock_prs()
    
    # Wait for background tasks
    print("\n\nWaiting 5 seconds for analysis to complete...")
    time.sleep(5)
    
    # Get results
    get_all_results()
