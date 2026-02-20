import { Navbar } from './components/Navbar';
import { Hero } from './components/Hero';
import { Features } from './components/Features';
import { TuiShowcase } from './components/TuiShowcase';
import { Analyzers } from './components/Analyzers';
import { Usage } from './components/Usage';
import { CiCd } from './components/CiCd';
import { Installation } from './components/Installation';
import { Footer } from './components/Footer';

function App() {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 selection:bg-blue-500/30">
      <Navbar />
      <main>
        <Hero />
        <Features />
        <TuiShowcase />
        <Analyzers />
        <Usage />
        <CiCd />
        <Installation />
      </main>
      <Footer />
    </div>
  );
}

export default App;
