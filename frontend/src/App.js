import React from "react";
import "./App.css";
import { HashRouter, Routes, Route } from "react-router-dom";
import AuditTool from "./components/AuditTool";
import { Toaster } from "./components/ui/toaster";

function App() {
  return (
    <div className="App">
      <HashRouter>
        <Routes>
          <Route path="/" element={<AuditTool />} />
        </Routes>
      </HashRouter>
      <Toaster />
    </div>
  );
}

export default App;