import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Textarea } from "./ui/textarea";
import { Badge } from "./ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { Alert, AlertDescription } from "./ui/alert";
import { Progress } from "./ui/progress";
import { Separator } from "./ui/separator";
import { Upload, FileText, Shield, AlertTriangle, XCircle, CheckCircle, Code, BookOpen, History, BarChart3 } from "lucide-react";
import { useToast } from "../hooks/use-toast";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const AuditTool = () => {
  const [contractCode, setContractCode] = useState("");
  const [auditResults, setAuditResults] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [auditHistory, setAuditHistory] = useState([]);
  const [auditStats, setAuditStats] = useState(null);
  const { toast } = useToast();

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file && file.name.endsWith('.sol')) {
      setUploadedFile(file);
      const reader = new FileReader();
      reader.onload = (e) => {
        setContractCode(e.target.result);
        toast({
          title: "File uploaded successfully",
          description: `${file.name} has been loaded into the editor.`,
        });
      };
      reader.readAsText(file);
    } else {
      toast({
        title: "Invalid file type",
        description: "Please upload a .sol file.",
        variant: "destructive",
      });
    }
  };

  const analyzeContract = async () => {
    if (!contractCode.trim()) {
      toast({
        title: "No code to analyze",
        description: "Please paste your Solidity code or upload a .sol file.",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    
    try {
      const response = await axios.post(`${API}/analyze`, {
        contract_code: contractCode,
        filename: uploadedFile?.name || "Pasted Code"
      });
      
      setAuditResults(response.data);
      toast({
        title: "Analysis complete",
        description: `Found ${response.data.vulnerabilities.length} potential vulnerabilities.`,
      });
      
      // Refresh history after successful analysis
      fetchAuditHistory();
      
    } catch (error) {
      console.error("Analysis error:", error);
      toast({
        title: "Analysis failed",
        description: error.response?.data?.detail || "An error occurred during analysis.",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const analyzeFile = async (file) => {
    setIsAnalyzing(true);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await axios.post(`${API}/analyze-file`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      setAuditResults(response.data);
      setContractCode(""); // Clear the text area since we're using file
      toast({
        title: "File analysis complete",
        description: `Found ${response.data.vulnerabilities.length} potential vulnerabilities in ${file.name}.`,
      });
      
      fetchAuditHistory();
      
    } catch (error) {
      console.error("File analysis error:", error);
      toast({
        title: "File analysis failed",
        description: error.response?.data?.detail || "An error occurred during file analysis.",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const fetchAuditHistory = async () => {
    try {
      const response = await axios.get(`${API}/history`);
      setAuditHistory(response.data.history);
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  };

  const fetchAuditStats = async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setAuditStats(response.data);
    } catch (error) {
      console.error("Error fetching stats:", error);
    }
  };

  React.useEffect(() => {
    fetchAuditHistory();
    fetchAuditStats();
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500 hover:bg-red-600';
      case 'high': return 'bg-orange-500 hover:bg-orange-600';
      case 'medium': return 'bg-yellow-500 hover:bg-yellow-600';
      case 'low': return 'bg-blue-500 hover:bg-blue-600';
      case 'info': return 'bg-gray-500 hover:bg-gray-600';
      default: return 'bg-gray-500 hover:bg-gray-600';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <XCircle className="h-4 w-4" />;
      case 'high': return <AlertTriangle className="h-4 w-4" />;
      case 'medium': return <AlertTriangle className="h-4 w-4" />;
      case 'low': return <CheckCircle className="h-4 w-4" />;
      default: return <CheckCircle className="h-4 w-4" />;
    }
  };

  const loadHistoryItem = async (auditId) => {
    try {
      const response = await axios.get(`${API}/history/${auditId}`);
      setAuditResults(response.data);
      setContractCode(response.data.contract_code);
      toast({
        title: "Audit loaded",
        description: `Loaded audit results for ${response.data.filename}.`,
      });
    } catch (error) {
      console.error("Error loading history item:", error);
      toast({
        title: "Error loading audit",
        description: "Failed to load the selected audit.",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="h-12 w-12 text-cyan-400 mr-3" />
            <h1 className="text-5xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
              Smart Contract Auditor
            </h1>
          </div>
          <p className="text-xl text-slate-300 max-w-2xl mx-auto">
            Comprehensive Solidity security analysis detecting reentrancy, overflow/underflow, 
            privilege escalation, and all major vulnerability patterns.
          </p>
        </div>

        {/* Stats Bar */}
        {auditStats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <BarChart3 className="h-5 w-5 text-cyan-400" />
                  <div>
                    <div className="text-2xl font-bold text-slate-100">{auditStats.total_audits}</div>
                    <div className="text-sm text-slate-400">Total Audits</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                  <div>
                    <div className="text-2xl font-bold text-slate-100">{auditStats.vulnerability_breakdown.critical}</div>
                    <div className="text-sm text-slate-400">Critical Issues</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <Shield className="h-5 w-5 text-yellow-400" />
                  <div>
                    <div className="text-2xl font-bold text-slate-100">{auditStats.total_vulnerabilities}</div>
                    <div className="text-sm text-slate-400">Total Vulnerabilities</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <History className="h-5 w-5 text-green-400" />
                  <div>
                    <div className="text-2xl font-bold text-slate-100">{auditStats.average_vulnerabilities_per_audit}</div>
                    <div className="text-sm text-slate-400">Avg per Audit</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Input Section */}
          <Card className="lg:col-span-2 bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="flex items-center text-slate-100">
                <Code className="h-5 w-5 mr-2 text-cyan-400" />
                Contract Input
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* File Upload */}
              <div className="border-2 border-dashed border-slate-600 rounded-lg p-6 text-center hover:border-cyan-400 transition-colors">
                <input
                  type="file"
                  accept=".sol"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="file-upload"
                />
                <label htmlFor="file-upload" className="cursor-pointer">
                  <Upload className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
                  <p className="text-slate-300 mb-2">Upload Solidity File</p>
                  <p className="text-sm text-slate-500">or drag and drop a .sol file</p>
                  {uploadedFile && (
                    <Badge variant="secondary" className="mt-2">
                      <FileText className="h-3 w-3 mr-1" />
                      {uploadedFile.name}
                    </Badge>
                  )}
                </label>
              </div>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <Separator className="w-full bg-slate-600" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-slate-800 px-2 text-slate-400">Or paste code</span>
                </div>
              </div>

              {/* Code Editor */}
              <div className="space-y-2">
                <Textarea
                  placeholder="pragma solidity ^0.8.0;

contract Example {
    // Paste your Solidity code here...
}"
                  value={contractCode}
                  onChange={(e) => setContractCode(e.target.value)}
                  className="min-h-[300px] font-mono text-sm bg-slate-900 border-slate-600 text-slate-100 resize-none"
                />
              </div>

              <Button 
                onClick={analyzeContract}
                disabled={isAnalyzing}
                className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white font-semibold py-3"
              >
                {isAnalyzing ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Analyzing Contract...
                  </>
                ) : (
                  <>
                    <Shield className="h-4 w-4 mr-2" />
                    Start Security Audit
                  </>
                )}
              </Button>

              {isAnalyzing && (
                <div className="space-y-2">
                  <Progress value={66} className="w-full" />
                  <p className="text-sm text-slate-400 text-center">
                    Running comprehensive security analysis...
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* History Section */}
          <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="flex items-center text-slate-100">
                <History className="h-5 w-5 mr-2 text-cyan-400" />
                Recent Audits
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 max-h-[400px] overflow-y-auto">
                {auditHistory.map((item, index) => (
                  <div 
                    key={item.id}
                    className="p-3 bg-slate-900/50 rounded-lg cursor-pointer hover:bg-slate-900/70 transition-colors"
                    onClick={() => loadHistoryItem(item.id)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-slate-200 truncate">
                        {item.filename}
                      </span>
                      <Badge variant="outline" className="text-xs">
                        {item.vulnerabilities_count} issues
                      </Badge>
                    </div>
                    <div className="text-xs text-slate-400">
                      Score: {item.summary.securityScore}/100 • {new Date(item.timestamp).toLocaleDateString()}
                    </div>
                  </div>
                ))}
                {auditHistory.length === 0 && (
                  <div className="text-center py-8">
                    <History className="h-12 w-12 text-slate-600 mx-auto mb-2" />
                    <p className="text-slate-400">No audit history yet</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Results Section */}
        {auditResults && (
          <>
            <Card className="mt-8 bg-slate-800/50 border-slate-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center justify-between text-slate-100">
                  <div className="flex items-center">
                    <BookOpen className="h-5 w-5 mr-2 text-cyan-400" />
                    Audit Results - {auditResults.filename}
                  </div>
                  <Badge variant="outline" className="text-slate-300">
                    {new Date(auditResults.timestamp).toLocaleString()}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  {/* Summary */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-slate-900/50 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-red-400">
                        {auditResults.summary.criticalIssues}
                      </div>
                      <div className="text-sm text-slate-400">Critical Issues</div>
                    </div>
                    <div className="bg-slate-900/50 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-orange-400">
                        {auditResults.summary.highIssues}
                      </div>
                      <div className="text-sm text-slate-400">High Issues</div>
                    </div>
                    <div className="bg-slate-900/50 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-yellow-400">
                        {auditResults.summary.totalIssues}
                      </div>
                      <div className="text-sm text-slate-400">Total Issues</div>
                    </div>
                    <div className="bg-slate-900/50 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-cyan-400">
                        {auditResults.summary.securityScore}
                      </div>
                      <div className="text-sm text-slate-400">Security Score</div>
                    </div>
                  </div>

                  {/* Security Score Alert */}
                  <Alert className="border-yellow-500 bg-yellow-500/10">
                    <AlertTriangle className="h-4 w-4 text-yellow-500" />
                    <AlertDescription className="text-slate-200">
                      <strong>Security Assessment:</strong><br />
                      {auditResults.summary.recommendation}
                    </AlertDescription>
                  </Alert>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="mt-8 bg-slate-800/50 border-slate-700 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-slate-100">Vulnerability Details</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="vulnerabilities" className="w-full">
                  <TabsList className="grid w-full grid-cols-2 bg-slate-900">
                    <TabsTrigger value="vulnerabilities" className="data-[state=active]:bg-cyan-500">
                      Vulnerabilities ({auditResults.vulnerabilities.length})
                    </TabsTrigger>
                    <TabsTrigger value="recommendations" className="data-[state=active]:bg-cyan-500">
                      Recommendations
                    </TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="vulnerabilities" className="space-y-4">
                    {auditResults.vulnerabilities.length === 0 ? (
                      <Alert className="border-green-500 bg-green-500/10">
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <AlertDescription className="text-slate-200">
                          <strong>No vulnerabilities detected!</strong><br />
                          Your contract appears to follow security best practices.
                        </AlertDescription>
                      </Alert>
                    ) : (
                      auditResults.vulnerabilities.map((vuln, index) => (
                        <Card key={index} className="bg-slate-900/50 border-slate-600">
                          <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-2">
                                {getSeverityIcon(vuln.severity)}
                                <CardTitle className="text-lg text-slate-100">{vuln.title}</CardTitle>
                              </div>
                              <Badge className={getSeverityColor(vuln.severity)}>
                                {vuln.severity}
                              </Badge>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-4">
                            <p className="text-slate-300">{vuln.description}</p>
                            
                            <div className="space-y-2">
                              <h4 className="font-semibold text-slate-200">Location:</h4>
                              <Badge variant="outline" className="border-slate-600 text-slate-300">
                                Line {vuln.line}: {vuln.function}()
                              </Badge>
                            </div>

                            <div className="space-y-2">
                              <h4 className="font-semibold text-slate-200">Vulnerable Code:</h4>
                              <pre className="bg-slate-950 p-3 rounded border border-slate-700 text-sm text-slate-300 overflow-x-auto">
                                <code>{vuln.codeSnippet}</code>
                              </pre>
                            </div>

                            <div className="space-y-2">
                              <h4 className="font-semibold text-slate-200">Recommendation:</h4>
                              <p className="text-slate-400 text-sm">{vuln.recommendation}</p>
                            </div>

                            {vuln.fixedCode && (
                              <div className="space-y-2">
                                <h4 className="font-semibold text-slate-200">Suggested Fix:</h4>
                                <pre className="bg-green-950/20 p-3 rounded border border-green-800 text-sm text-green-300 overflow-x-auto">
                                  <code>{vuln.fixedCode}</code>
                                </pre>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))
                    )}
                  </TabsContent>

                  <TabsContent value="recommendations" className="space-y-4">
                    {auditResults.recommendations.map((rec, index) => (
                      <Alert key={index} className="border-blue-500 bg-blue-500/10">
                        <CheckCircle className="h-4 w-4 text-blue-500" />
                        <AlertDescription className="text-slate-200">
                          <strong>{rec.category}:</strong> {rec.description}
                        </AlertDescription>
                      </Alert>
                    ))}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </div>
  );
};

export default AuditTool;