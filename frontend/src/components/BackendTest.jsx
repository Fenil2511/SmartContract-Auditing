import React, { useState } from 'react';
import axios from 'axios';

const BackendTest = () => {
  const [testResult, setTestResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const testBackend = async () => {
    setLoading(true);
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:10000';
      
      // Test health endpoint
      const healthResponse = await axios.get(`${backendUrl}/api/`);
      console.log('Health check response:', healthResponse.data);
      
      // Test analysis endpoint
      const analysisResponse = await axios.post(`${backendUrl}/api/analyze`, {
        contract_code: "pragma solidity ^0.8.0; contract Test {}"
      });
      console.log('Analysis response:', analysisResponse.data);
      
      setTestResult({
        success: true,
        health: healthResponse.data,
        analysis: analysisResponse.data,
        backendUrl
      });
    } catch (error) {
      console.error('Backend test failed:', error);
      setTestResult({
        success: false,
        error: error.message,
        backendUrl: process.env.REACT_APP_BACKEND_URL || 'Not set'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4 border rounded-lg bg-slate-800">
      <h3 className="text-lg font-bold mb-4">Backend Connection Test</h3>
      
      <button 
        onClick={testBackend}
        disabled={loading}
        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
      >
        {loading ? 'Testing...' : 'Test Backend Connection'}
      </button>
      
      {testResult && (
        <div className="mt-4">
          <h4 className="font-semibold mb-2">
            {testResult.success ? '✅ Backend Connected!' : '❌ Backend Connection Failed'}
          </h4>
          
          <div className="text-sm">
            <p><strong>Backend URL:</strong> {testResult.backendUrl}</p>
            
            {testResult.success ? (
              <div>
                <p><strong>Health Check:</strong> ✅ Working</p>
                <p><strong>Analysis Test:</strong> ✅ Working</p>
                <details className="mt-2">
                  <summary className="cursor-pointer">View Response Details</summary>
                  <pre className="mt-2 p-2 bg-slate-900 rounded text-xs overflow-auto">
                    {JSON.stringify(testResult, null, 2)}
                  </pre>
                </details>
              </div>
            ) : (
              <div>
                <p><strong>Error:</strong> {testResult.error}</p>
                <p className="text-red-400 mt-2">
                  Make sure your backend is deployed and REACT_APP_BACKEND_URL is set correctly.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default BackendTest; 