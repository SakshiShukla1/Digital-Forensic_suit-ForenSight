import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Shield, Globe, Mail, FileSearch, Activity, Loader2, Terminal, ChevronRight, Download, Cpu } from 'lucide-react';

function App() {
  const [activeModule, setActiveModule] = useState('URL');
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [evidenceLog, setEvidenceLog] = useState([]);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [currentCase, setCurrentCase] = useState(null);
  const [caseInput, setCaseInput] = useState('');
  const [showModal, setShowModal] = useState(true);
  const [viewMode, setViewMode] = useState('new');
  const [allCases, setAllCases] = useState([]);
  
  // NEW: Terminal State
  const [terminalLog, setTerminalLog] = useState(["[SYSTEM] Forensight Terminal v2.0.4 initialized...", "[READY] Awaiting Case Assignment..."]);
  const terminalRef = useRef(null);

  // Auto-scroll terminal to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLog]);

  useEffect(() => {
    if (viewMode === 'archive') {
      axios.get('http://localhost:8000/api/get-all-cases').then(res => setAllCases(res.data));
    }
  }, [viewMode]);

  const addLog = (msg) => {
    const time = new Date().toLocaleTimeString();
    setTerminalLog(prev => [...prev, `[${time}] ${msg}`]);
  };

  const handleScan = async () => {
    if (!currentCase) return;
    setLoading(true);
    addLog(`INITIATING ${activeModule} SCAN...`);
    
    try {
      const urlBase = 'http://localhost:8000/api';
      let res;
      let targetDisplay = inputValue;

      if (activeModule === 'URL') {
        addLog(`Analyzing Reputation for: ${inputValue}`);
        const fd = new FormData(); fd.append('url', inputValue);
        res = await axios.post(`${urlBase}/analyze-url`, fd);
      } else if (activeModule === 'Email') {
        addLog(`Parsing Email Headers and Content...`);
        const fd = new FormData(); fd.append('content', inputValue);
        res = await axios.post(`${urlBase}/analyze-email`, fd);
      } else if (activeModule === 'File') {
        const fileInput = document.getElementById('file-upload');
        if (!fileInput.files[0]) return;
        targetDisplay = fileInput.files[0].name;
        addLog(`Uploading Artifact: ${targetDisplay}`);
        const fd = new FormData(); fd.append('file', fileInput.files[0]);
        res = await axios.post(`${urlBase}/analyze-file`, fd);
      } else {
        addLog(`Accessing System Browser Databases (Chrome/Edge/Firefox)...`);
        res = await axios.get(`${urlBase}/browser-scan`);
      }

      const rawData = res.data;
      const finalScore = rawData.score !== undefined ? rawData.score : (rawData.risk_score || 0);
      
      addLog(`Analysis Complete. Risk Index: ${finalScore}%`);
      addLog(`Verdict: ${rawData.verdict || "COMPLETED"}`);

      const newEvidence = {
        type: activeModule,
        target: targetDisplay,
        score: finalScore,
        verdict: rawData.verdict || "DONE",
        timestamp: new Date().toLocaleTimeString(),
        rawData: rawData 
      };

      const saveFd = new FormData();
      saveFd.append('case_id', currentCase.id);
      saveFd.append('type', newEvidence.type);
      saveFd.append('target', newEvidence.target);
      saveFd.append('score', newEvidence.score);
      saveFd.append('verdict', newEvidence.verdict);
      saveFd.append('findings', JSON.stringify(rawData.summary || {})); 
      saveFd.append('raw_json', JSON.stringify(rawData));
      
      await axios.post(`${urlBase}/save-evidence`, saveFd);
      setEvidenceLog([newEvidence, ...evidenceLog]);
      setSelectedEvidence(newEvidence);
      setInputValue('');
      addLog(`Evidence committed to Case ${currentCase.id}`);

    } catch (e) { 
      addLog(`ERROR: Module Communication Failure.`);
      console.error(e); 
    }
    setLoading(false);
  };

  const downloadReport = async () => {
    addLog(`Generating PDF Forensic Report...`);
    try {
      const res = await axios.get(`http://localhost:8000/api/generate-report/${currentCase.id}`);
      window.open(res.data.report_url, '_blank');
      addLog(`Report successfully exported.`);
    } catch { addLog(`ERROR: Report generation failed.`); }
  };

  return (
    <div className="flex h-screen bg-[#05070a] text-slate-300 font-mono overflow-hidden">
      {/* CASE MODAL */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm">
          <div className="bg-[#0f172a] border border-blue-500/20 w-[450px] rounded-xl p-8 shadow-2xl">
            <h2 className="text-white text-lg font-bold mb-6 flex items-center gap-2"><Terminal size={18} className="text-blue-500"/> CASE_INITIALIZATION</h2>
            <div className="flex mb-6 bg-black/40 rounded-lg p-1">
              <button onClick={()=>setViewMode('new')} className={`flex-1 py-2 text-[10px] rounded-md transition ${viewMode==='new' ? 'bg-blue-600 text-white' : 'text-slate-500'}`}>NEW_INVESTIGATION</button>
              <button onClick={()=>setViewMode('archive')} className={`flex-1 py-2 text-[10px] rounded-md transition ${viewMode==='archive' ? 'bg-blue-600 text-white' : 'text-slate-500'}`}>ACCESS_ARCHIVES</button>
            </div>
            {viewMode === 'new' ? (
              <div className="space-y-4">
                <input className="w-full bg-black border border-slate-800 p-3 rounded text-blue-400 text-xs focus:border-blue-500 outline-none" placeholder="Enter Case Identifier..." value={caseInput} onChange={(e)=>setCaseInput(e.target.value)} />
                <button onClick={async()=>{
                  const fd = new FormData(); fd.append('case_name', caseInput);
                  const r = await axios.post('http://localhost:8000/api/create-case', fd);
                  setCurrentCase(r.data); setShowModal(false);
                  addLog(`Nexus Established: Case ${r.data.id}`);
                }} className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded text-[10px] font-bold text-white uppercase tracking-widest transition">Establish Nexus</button>
              </div>
            ) : (
              <div className="space-y-2 max-h-60 overflow-y-auto pr-2 custom-scroll">
                {allCases.map(c => (
                  <div key={c.id} onClick={async()=>{
                    setCurrentCase(c); 
                    const r = await axios.get(`http://localhost:8000/api/get-case-history/${c.id}`);
                    setEvidenceLog(r.data.map(e => ({...e, rawData: JSON.parse(e.raw_json)})));
                    setShowModal(false);
                    addLog(`Archive Restored: ${c.name}`);
                  }} className="p-4 bg-black/40 border border-slate-800 rounded-lg hover:border-blue-500 cursor-pointer group flex justify-between items-center transition">
                    <div>
                      <div className="text-blue-400 text-[11px] font-bold">{c.name}</div>
                      <div className="text-slate-600 text-[9px] mt-1">{c.created_at}</div>
                    </div>
                    <ChevronRight size={14} className="text-slate-700 group-hover:text-blue-500" />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SIDEBAR */}
      <div className="w-64 border-r border-slate-900 bg-[#020408] p-6 flex flex-col">
        <div className="flex items-center gap-3 mb-10 text-white font-black tracking-tighter text-xl">
          <div className="bg-blue-600 p-1.5 rounded-lg"><Shield size={20} fill="white"/></div>
          FORENSIGHT
        </div>
        <nav className="space-y-2 flex-1">
          {[
            { id: 'URL', icon: <Globe size={14}/> },
            { id: 'Email', icon: <Mail size={14}/> },
            { id: 'File', icon: <FileSearch size={14}/> },
            { id: 'Browser', icon: <Activity size={14}/> }
          ].map(m => (
            <button key={m.id} onClick={()=>{setActiveModule(m.id); setInputValue(""); addLog(`Switched to ${m.id} module.`);}} 
              className={`w-full flex items-center gap-3 p-3 text-[10px] font-bold rounded-xl transition-all ${activeModule===m.id ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20' : 'text-slate-500 hover:bg-slate-900'}`}>
              {m.icon} {m.id.toUpperCase()}_ANALYSIS
            </button>
          ))}
        </nav>
        <div className="mt-auto space-y-3">
          <div className="p-4 bg-slate-900/30 rounded-xl border border-slate-800/50">
            <div className="text-[8px] text-slate-500 uppercase mb-1">Active_Case</div>
            <div className="text-[10px] text-blue-400 font-bold truncate">{currentCase?.name || "OFFLINE"}</div>
          </div>
          <button onClick={downloadReport} className="w-full flex items-center justify-center gap-2 border border-blue-500/30 text-blue-500 text-[9px] py-3 rounded-xl hover:bg-blue-600 hover:text-white transition-all uppercase font-black tracking-widest">
            <Download size={12}/> Export_Report
          </button>
        </div>
      </div>

      {/* CENTER PANEL */}
      <div className="flex-1 flex flex-col bg-[#05070a] min-w-0">
        <header className="h-24 border-b border-slate-900 flex items-center px-8 gap-6 bg-[#05070a]/80 backdrop-blur-md z-10">
          <div className="flex-1 relative">
            {activeModule === 'File' ? (
              <input type="file" id="file-upload" className="w-full text-[10px] file:bg-blue-600/10 file:text-blue-400 file:border-0 file:rounded-md file:px-4 file:py-2 file:mr-4 file:cursor-pointer" />
            ) : (
              <input className="w-full bg-slate-900/50 border border-slate-800 p-4 rounded-xl text-xs text-white placeholder:text-slate-700 focus:border-blue-600 outline-none transition" 
                placeholder={`Input ${activeModule} for analysis...`} value={inputValue} onChange={(e)=>setInputValue(e.target.value)} />
            )}
          </div>
          <button onClick={handleScan} disabled={loading} className="bg-blue-600 hover:bg-blue-500 px-8 py-4 rounded-xl text-[10px] font-black text-white uppercase tracking-[0.2em] shadow-lg shadow-blue-600/20 disabled:opacity-50 transition-all flex items-center gap-2">
            {loading ? <Loader2 className="animate-spin" size={14} /> : 'Execute_Scan'}
          </button>
        </header>

        {/* LOG TABLE */}
        <div className="flex-1 overflow-auto custom-scroll">
          <table className="w-full text-left border-collapse">
            <thead className="text-[9px] text-slate-500 uppercase sticky top-0 bg-[#05070a] z-10">
              <tr className="border-b border-slate-900">
                <th className="p-6">Origin_Module</th>
                <th className="p-6">Target_Artifact</th>
                <th className="p-6">Risk_Index</th>
                <th className="p-6 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="text-[11px]">
              {evidenceLog.map((item, idx) => (
                <tr key={idx} onClick={()=>setSelectedEvidence(item)} className={`border-b border-slate-900/30 cursor-pointer transition-colors ${selectedEvidence===item?'bg-blue-600/10':'hover:bg-slate-900/40'}`}>
                  <td className="p-6"><span className="px-2 py-1 bg-slate-900 rounded text-blue-400 font-bold text-[9px]">{item.type}</span></td>
                  <td className="p-6 text-slate-300 font-medium truncate max-w-[200px]">{item.target}</td>
                  <td className={`p-6 font-black ${item.score > 50 ? 'text-red-500' : 'text-emerald-500'}`}>{item.score}%</td>
                  <td className="p-6 text-slate-600 text-right tabular-nums">{item.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* NEW: LIVE TERMINAL PANEL */}
        <div className="h-48 border-t border-slate-900 bg-black/40 p-4 font-mono">
          <div className="flex items-center gap-2 mb-2 text-[10px] text-slate-600 uppercase font-bold tracking-widest">
            <Cpu size={12}/> Subsystem_Process_Logs
          </div>
          <div ref={terminalRef} className="h-32 overflow-y-auto text-[10px] text-emerald-500/80 custom-scroll space-y-1">
            {terminalLog.map((log, i) => (
              <div key={i} className="flex gap-2">
                <span className="text-blue-900 font-bold">»</span> {log}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* RIGHT PANEL - DYNAMIC INSPECTOR */}
      <div className="w-96 border-l border-slate-900 bg-[#020408] flex flex-col">
        {selectedEvidence ? (
          <div className="p-8 overflow-y-auto custom-scroll flex-1">
            <div className="text-[9px] text-blue-500 font-bold tracking-[0.3em] mb-8">ARTIFACT_INSPECTOR_V2</div>
            
            <div className="mb-10 relative">
              <div className="text-[8px] text-slate-600 uppercase mb-2 font-bold">Threat_Probability</div>
              <div className="flex items-end gap-2">
                <div className="text-6xl font-black text-white leading-none">{selectedEvidence.score}<span className="text-xl text-slate-700">%</span></div>
                <div className={`text-[10px] font-bold uppercase pb-1 ${selectedEvidence.score > 50 ? 'text-red-500' : 'text-emerald-500'}`}>
                  // {selectedEvidence.verdict}
                </div>
              </div>
            </div>

            <div className="space-y-6">
              {/* FILE MODULE */}
              {selectedEvidence.type === 'File' && selectedEvidence.rawData.summary && (
                <div className="space-y-4">
                  <div className="p-4 bg-slate-900/50 rounded-xl border border-slate-800">
                    <div className="text-[8px] text-slate-600 uppercase mb-1">MIME_TYPE</div>
                    <div className="text-xs text-blue-300">{selectedEvidence.rawData.summary.mime_type}</div>
                  </div>
                  <div className="p-4 bg-slate-900/50 rounded-xl border border-slate-800">
                    <div className="text-[8px] text-slate-600 uppercase mb-1">SHA256_HASH</div>
                    <div className="text-[9px] text-slate-400 break-all leading-relaxed">{selectedEvidence.rawData.summary.sha256}</div>
                  </div>
                </div>
              )}

              {/* URL MODULE */}
              {selectedEvidence.type === 'URL' && selectedEvidence.rawData.summary && (
                <div className="p-4 bg-slate-900/50 rounded-xl border border-slate-800">
                  <div className="text-[8px] text-slate-600 uppercase mb-1">TARGET_DOMAIN</div>
                  <div className="text-xs text-blue-300 break-all">{selectedEvidence.rawData.summary.domain}</div>
                </div>
              )}

              {/* BROWSER MODULE */}
              {selectedEvidence.type === 'Browser' && selectedEvidence.rawData.summary && (
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 bg-slate-900/50 rounded-xl border border-slate-800">
                    <div className="text-[8px] text-slate-600 uppercase">Records</div>
                    <div className="text-xl font-bold text-white">{selectedEvidence.rawData.summary.total_records}</div>
                  </div>
                  <div className="p-4 bg-red-900/20 rounded-xl border border-red-900/30">
                    <div className="text-[8px] text-red-500 uppercase">Suspicious</div>
                    <div className="text-xl font-bold text-red-500">{selectedEvidence.rawData.summary.suspicious_records}</div>
                  </div>
                </div>
              )}

              <div className="mt-8 pt-8 border-t border-slate-900">
                <div className="text-[8px] text-slate-600 uppercase mb-4 font-bold tracking-widest">Risk_Telemetry</div>
                {(selectedEvidence.rawData.indicators || selectedEvidence.rawData.top_findings || []).map((ind, i) => (
                  <div key={i} className="mb-2 p-3 bg-red-500/5 border-l-2 border-red-500 rounded-r-lg">
                    <div className="text-[9px] text-red-400 font-bold uppercase">{ind.type || ind.browser || "ALERT"}</div>
                    <div className="text-[10px] text-slate-500 mt-1 truncate">{ind.details || ind.domain || "Pattern mismatch."}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center opacity-30">
            <Activity className="text-slate-500 mb-4" size={48} />
            <div className="text-[10px] text-slate-700 font-bold uppercase tracking-[0.2em]">Idle_System</div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;