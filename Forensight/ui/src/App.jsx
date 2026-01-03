import React, { useState } from 'react';
import axios from 'axios';
import { 
  Shield, Globe, Mail, FileSearch, Activity, 
  Terminal, AlertCircle, Plus, Folder, FileText, 
  ChevronRight, ChevronDown, LayoutGrid, List 
} from 'lucide-react';

function App() {
  // --- STATE MANAGEMENT ---
  const [activeModule, setActiveModule] = useState('URL');
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  
  // Case & Evidence Management
  const [cases, setCases] = useState([{ id: 1, name: "Incident #2024-001", evidence: [] }]);
  const [currentCase, setCurrentCase] = useState(cases[0]);
  const [evidenceLog, setEvidenceLog] = useState([]); // This stores ALL your scans
  const [selectedEvidence, setSelectedEvidence] = useState(null); // Which row is clicked?

  // --- ACTIONS ---
  const handleCreateCase = () => {
    const caseName = window.prompt("Enter Case Name (e.g., 'Phishing Incident #101'):");
    if (caseName) {
      const newCase = { id: Date.now(), name: caseName, evidence: [] };
      setCases([...cases, newCase]);
      setCurrentCase(newCase);
      setEvidenceLog([]); // Clear view for new case
    }
  };

  const handleScan = async () => {
    if (!inputValue && activeModule !== 'Browser') return;
    
    setLoading(true);
    try {
      let response;
      if (activeModule === 'URL') {
        const formData = new FormData();
        formData.append('url', inputValue);
        response = await axios.post('http://localhost:8000/api/analyze-url', formData);
      } else if (activeModule === 'Browser') {
        response = await axios.get('http://localhost:8000/api/browser-scan');
      }

      // ADD TO EVIDENCE LOG (The Forensic Way)
      const newEvidence = {
        id: Date.now(),
        type: activeModule,
        target: inputValue || "System Browser",
        timestamp: new Date().toLocaleTimeString(),
        score: response.data.score,
        verdict: response.data.verdict,
        details: response.data.findings_list
      };

      // Add to the top of the list
      setEvidenceLog([newEvidence, ...evidenceLog]);
      setSelectedEvidence(newEvidence); // Auto-select the new item
      setInputValue(""); 

    } catch (error) {
      console.error("Scan failed", error);
      alert("Backend Error: Check your Python terminal.");
    }
    setLoading(false);
  };


  // --- REPORT GENERATION ---
const handleExportReport = () => {
  if (evidenceLog.length === 0) {
    alert("No evidence to report!");
    return;
  }

  // 1. Build the text content
  let content = `FORENSIGHT INVESTIGATION REPORT\n`;
  content += `CASE ID: ${currentCase.id}\n`;
  content += `CASE NAME: ${currentCase.name}\n`;
  content += `GENERATED: ${new Date().toLocaleString()}\n`;
  content += `--------------------------------------------\n\n`;

  evidenceLog.forEach((item, index) => {
    content += `EVIDENCE #${evidenceLog.length - index} [${item.type}]\n`;
    content += `Target: ${item.target}\n`;
    content += `Verdict: ${item.verdict} (Risk: ${item.score}%)\n`;
    content += `Timestamp: ${item.timestamp}\n`;
    content += `Details: ${item.details.join(", ")}\n`;
    content += `--------------------------------------------\n`;
  });

  // 2. Create a "Blob" (Virtual File)
  const element = document.createElement("a");
  const file = new Blob([content], {type: 'text/plain'});
  
  // 3. Trigger Download
  element.href = URL.createObjectURL(file);
  element.download = `Case_${currentCase.id}_Report.txt`;
  document.body.appendChild(element);
  element.click();
};

  return (
    <div className="flex h-screen bg-[#0b0f19] text-slate-300 font-sans overflow-hidden">
      
      {/* --- 1. LEFT PANE: CASE EXPLORER (Tree View) --- */}
      <div className="w-64 bg-[#05080f] border-r border-slate-800 flex flex-col">
        {/* Branding */}
        <div className="p-4 border-b border-slate-800 flex items-center gap-2">
          <Shield className="text-blue-500" size={20} />
          <h1 className="font-bold text-slate-100 tracking-wider">FORENSIGHT <span className="text-xs text-blue-500">PRO</span></h1>
        </div>

        {/* Case Selector */}
        <div className="p-4">
            <button onClick={handleCreateCase} className="w-full bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold py-2 px-3 rounded flex items-center justify-center gap-2">
                <Plus size={14} /> NEW CASE
            </button>
        </div>

        {/* The Tree Structure */}
        <div className="flex-1 overflow-y-auto px-2">
            <div className="mb-4">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-500 uppercase mb-2 px-2">
                    <Folder size={12} /> Active Case
                </div>
                <div className="bg-slate-900/50 rounded p-2 mb-2 border border-slate-700">
                    <div className="text-white font-mono text-sm truncate">{currentCase ? currentCase.name : "No Case"}</div>
                    <div className="text-[10px] text-slate-500 mt-1">ID: {currentCase?.id}</div>
                </div>

                {/* Modules as "Folders" */}
                <div className="space-y-1">
                    {['URL', 'Email', 'File', 'Browser'].map(mod => (
                        <div 
                            key={mod}
                            onClick={() => setActiveModule(mod)}
                            className={`flex items-center gap-2 px-3 py-2 rounded cursor-pointer text-sm ${activeModule === mod ? 'bg-blue-900/30 text-blue-400 border border-blue-900' : 'hover:bg-slate-900'}`}
                        >
                            {activeModule === mod ? <ChevronDown size={14}/> : <ChevronRight size={14}/>}
                            {mod === 'URL' && <Globe size={14} />}
                            {mod === 'Email' && <Mail size={14} />}
                            {mod === 'File' && <FileSearch size={14} />}
                            {mod === 'Browser' && <Activity size={14} />}
                            <span>{mod} Artifacts</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
      </div>

      {/* --- 2. MIDDLE PANE: EVIDENCE LIST (The Log) --- */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#0b0f19]">
        
        {/* Toolbar / Input Area */}
        <div className="h-16 border-b border-slate-800 flex items-center px-6 gap-4 bg-[#0f1522]">
            <div className="flex-1 flex items-center bg-black/40 border border-slate-700 rounded-md px-3 py-2">
                <Terminal size={16} className="text-slate-500 mr-3" />
                <input 
                    className="bg-transparent outline-none text-sm text-white w-full font-mono placeholder:text-slate-600"
                    placeholder={`Ingest new ${activeModule} evidence...`}
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                />
            </div>
            <button 
                onClick={handleScan}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded text-sm font-bold disabled:opacity-50"
            >
                {loading ? 'PROCESSING...' : 'ANALYZE'}
            </button>
            <button 
                onClick={handleExportReport}
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-2 rounded text-sm font-bold"
            >
                EXPORT REPORT
            </button>
        </div>

        {/* The Table Grid */}
        <div className="flex-1 overflow-auto p-0">
            <table className="w-full text-left border-collapse">
                <thead className="bg-[#05080f] text-xs uppercase text-slate-500 font-bold sticky top-0">
                    <tr>
                        <th className="p-3 border-b border-slate-800 w-12">ID</th>
                        <th className="p-3 border-b border-slate-800 w-24">Type</th>
                        <th className="p-3 border-b border-slate-800">Target / Source</th>
                        <th className="p-3 border-b border-slate-800 w-32">Risk Score</th>
                        <th className="p-3 border-b border-slate-800 w-32">Verdict</th>
                        <th className="p-3 border-b border-slate-800 w-24">Time</th>
                    </tr>
                </thead>
                <tbody className="text-sm font-mono">
                    {evidenceLog.length === 0 ? (
                        <tr>
                            <td colSpan="6" className="p-10 text-center text-slate-600 italic">
                                No evidence collected in this case yet.
                            </td>
                        </tr>
                    ) : (
                        evidenceLog.map((item, idx) => (
                            <tr 
                                key={item.id} 
                                onClick={() => setSelectedEvidence(item)}
                                className={`cursor-pointer border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors ${selectedEvidence?.id === item.id ? 'bg-blue-900/20' : ''}`}
                            >
                                <td className="p-3 text-slate-500">{idx + 1}</td>
                                <td className="p-3 text-blue-400">{item.type}</td>
                                <td className="p-3 text-white truncate max-w-xs">{item.target}</td>
                                <td className="p-3">
                                    <div className="w-full bg-slate-800 rounded-full h-1.5">
                                        <div 
                                            className={`h-1.5 rounded-full ${item.score > 50 ? 'bg-red-500' : 'bg-emerald-500'}`} 
                                            style={{ width: `${item.score}%` }}
                                        ></div>
                                    </div>
                                </td>
                                <td className={`p-3 font-bold ${item.score > 50 ? 'text-red-500' : 'text-emerald-500'}`}>
                                    {item.verdict}
                                </td>
                                <td className="p-3 text-slate-500">{item.timestamp}</td>
                            </tr>
                        ))
                    )}
                </tbody>
            </table>
        </div>
      </div>

      {/* --- 3. RIGHT PANE: INSPECTOR (Details) --- */}
      {selectedEvidence && (
        <div className="w-80 bg-[#0f1522] border-l border-slate-800 flex flex-col animate-in slide-in-from-right duration-300">
            <div className="p-4 border-b border-slate-800 bg-[#05080f]">
                <h3 className="font-bold text-white flex items-center gap-2">
                    <FileText size={16} className="text-blue-500"/> INSPECTOR
                </h3>
            </div>
            <div className="flex-1 overflow-auto p-4 space-y-6">
                
                {/* Risk Card */}
                <div className={`p-4 rounded border ${selectedEvidence.score > 50 ? 'border-red-900/50 bg-red-950/10' : 'border-emerald-900/50 bg-emerald-950/10'}`}>
                    <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">Threat Level</div>
                    <div className="text-3xl font-black text-white mb-2">{selectedEvidence.score}/100</div>
                    <div className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase ${selectedEvidence.score > 50 ? 'bg-red-900 text-red-200' : 'bg-emerald-900 text-emerald-200'}`}>
                        {selectedEvidence.verdict}
                    </div>
                </div>

                {/* Findings List */}
                <div>
                    <h4 className="text-xs font-bold text-slate-400 uppercase mb-3 flex items-center gap-2">
                        <Terminal size={12} /> Forensic Artifacts
                    </h4>
                    <ul className="space-y-2">
                        {selectedEvidence.details?.map((finding, i) => (
                            <li key={i} className="text-xs text-slate-300 bg-slate-900/50 p-2 rounded border-l-2 border-blue-500">
                                {finding}
                            </li>
                        ))}
                    </ul>
                </div>

                {/* Metadata */}
                <div className="pt-4 border-t border-slate-800">
                    <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-500 font-mono">
                        <div>TIMESTAMP:</div>
                        <div className="text-right text-slate-300">{selectedEvidence.timestamp}</div>
                        <div>MODULE:</div>
                        <div className="text-right text-slate-300">{selectedEvidence.type}</div>
                        <div>ID:</div>
                        <div className="text-right text-slate-300">EV-{selectedEvidence.id}</div>
                    </div>
                </div>

            </div>
        </div>
      )}
    </div>
  );
}

export default App;