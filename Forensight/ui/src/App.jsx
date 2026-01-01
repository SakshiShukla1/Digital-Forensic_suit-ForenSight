import React, { useState } from 'react';
import axios from 'axios';
import { Shield, Globe, Mail, FileSearch, Activity, Terminal, AlertCircle } from 'lucide-react';

function App() {
  const [activeModule, setActiveModule] = useState('URL');
  const [inputValue, setInputValue] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    setResult(null);
    try {
      let response;
      if (activeModule === 'URL') {
        const formData = new FormData();
        formData.append('url', inputValue);
        response = await axios.post('http://localhost:8000/api/analyze-url', formData);
      } else if (activeModule === 'Browser') {
        response = await axios.get('http://localhost:8000/api/browser-scan');
      }
      setResult(response.data);
    } catch (error) {
      console.error("Scan failed", error);
    }
    setLoading(false);
  };

  return (
    <div className="flex h-screen bg-[#020617] text-slate-200 font-sans">
      {/* SIDEBAR */}
      <div className="w-64 bg-[#0f172a] border-r border-slate-800 flex flex-col p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-12">
          <Shield className="text-blue-500" size={32} />
          <h1 className="text-xl font-black tracking-tighter text-white">FORENSIGHT</h1>
        </div>

        <nav className="space-y-2">
          {[
            { name: 'URL', icon: Globe },
            { name: 'Email', icon: Mail },
            { name: 'File', icon: FileSearch },
            { name: 'Browser', icon: Activity },
          ].map((mod) => (
            <button
              key={mod.name}
              onClick={() => {setActiveModule(mod.name); setResult(null); setInputValue('');}}
              className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all ${
                activeModule === mod.name ? 'bg-blue-600 text-white shadow-lg' : 'hover:bg-slate-800 text-slate-400'
              }`}
            >
              <mod.icon size={20} />
              <span className="font-semibold">{mod.name} Analysis</span>
            </button>
          ))}
        </nav>
      </div>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 p-10 overflow-auto bg-[radial-gradient(circle_at_top_right,_var(--tw-gradient-stops))] from-blue-900/10 via-transparent to-transparent">
        <header className="mb-12">
          <h2 className="text-4xl font-extrabold text-white mb-2">Forensic <span className="text-blue-500">Intelligence</span> Dashboard</h2>
          <p className="text-slate-400 font-medium">Professional grade digital evidence analysis engine.</p>
        </header>

        {/* INPUT BOX */}
        <div className="bg-[#1e293b]/50 border border-slate-700 p-8 rounded-3xl backdrop-blur-md shadow-2xl mb-10">
          <div className="flex gap-4">
            <input
              type="text"
              className="flex-1 bg-slate-900 border border-slate-600 rounded-2xl p-4 focus:ring-2 focus:ring-blue-500 outline-none transition-all font-mono text-blue-400"
              placeholder={activeModule === 'Browser' ? 'System ready for history scan...' : `Enter target ${activeModule} for investigation...`}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              disabled={activeModule === 'Browser'}
            />
            <button 
              onClick={handleScan}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-500 px-10 py-4 rounded-2xl font-bold flex items-center gap-2 transition-all active:scale-95 shadow-lg shadow-blue-900/40 text-white disabled:opacity-50"
            >
              {loading ? 'ANALYZING...' : 'RUN SCAN'}
              <Terminal size={18} />
            </button>
          </div>
        </div>

        {/* DYNAMIC RESULTS DISPLAY */}
        {result && (
          <div className="animate-in fade-in slide-in-from-bottom-5 duration-700">
            <div className={`p-8 rounded-3xl border-2 shadow-2xl ${result.score > 50 ? 'border-red-500 bg-red-950/20' : 'border-emerald-500 bg-emerald-950/20'}`}>
              <div className="flex justify-between items-start mb-8">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <AlertCircle className={result.score > 50 ? 'text-red-500' : 'text-emerald-500'} />
                    <span className="text-sm font-bold uppercase tracking-widest text-slate-400">Security Assessment</span>
                  </div>
                  <h3 className="text-4xl font-black italic uppercase tracking-wider text-white">VERDICT: {result.verdict}</h3>
                </div>
                <div className="text-right bg-slate-900/80 p-4 rounded-2xl border border-slate-700">
                  <span className="text-5xl font-black block text-white">{result.score || 0}%</span>
                  <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Risk Probability</span>
                </div>
              </div>
              
              <div className="bg-black/40 rounded-2xl p-6 font-mono text-sm border border-white/5 backdrop-blur-sm">
                <h4 className="text-blue-400 font-bold mb-4 flex items-center gap-2">
                  <Terminal size={16} /> FORENSIC_LOG_OUTPUT:
                </h4>
                <ul className="space-y-3">
                  {result.findings_list?.map((f, i) => (
                    <li key={i} className="flex gap-3 text-slate-300">
                      <span className="text-blue-600 font-bold">[{i+1}]</span> {f}
                    </li>
                  ))}
                  {activeModule === 'Browser' && (
                    <li className="text-blue-400 font-bold border-t border-slate-800 pt-3">
                      TOTAL EVIDENCE RECORDS RETRIEVED: {result.total_records}
                    </li>
                  )}
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;