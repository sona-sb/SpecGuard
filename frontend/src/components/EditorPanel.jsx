import { FileCode2 } from "lucide-react";

export default function EditorPanel({ title, filename, value, onChange, language }) {
  return (
    <section className="retro-shadow overflow-hidden border-2 border-[#1e3d2f] border-t-white/20 border-l-white/10 border-b-4 border-r-4 border-b-black/60 border-r-black/60 bg-[#13291f]">
      <header className="flex items-center justify-between border-b border-[#1e3d2f] px-4 py-3">
        <div className="flex items-center gap-2 text-[#c4b5fd]">
          <FileCode2 size={16} />
          <span className="pixel-label text-[10px]">{title}</span>
        </div>
        <span className="bg-[#0b1a12] px-2 py-1 text-xs text-[#94a3b8]">{filename}</span>
      </header>
      <textarea
        aria-label={title}
        spellCheck="false"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={`Paste ${language} here...`}
        className="mono-copy min-h-[310px] w-full resize-y bg-[#0b1a12] p-4 text-[15px] leading-6 text-[#f8fafc] outline-none placeholder:text-[#64748b]"
      />
      <footer className="border-t border-[#1e3d2f] px-4 py-2 text-xs text-[#94a3b8]">{value.length.toLocaleString()} chars</footer>
    </section>
  );
}
