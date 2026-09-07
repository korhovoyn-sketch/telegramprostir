const ts=require('typescript'), fs=require('fs')
const {walkFiles,CYR}=require('./extract.js')
let split=[]
for(const f of walkFiles('src')){
  const src=ts.createSourceFile(f,fs.readFileSync(f,'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX)
  const visit=n=>{
    if(ts.isJsxElement(n)){
      const texts=(n.children||[]).filter(c=>ts.isJsxText(c)&&CYR.test(c.getText()))
      if(texts.length>=2){
        const {line}=src.getLineAndCharacterOfPosition(n.getStart())
        split.push({f,line:line+1,parts:texts.map(t=>t.getText().trim().replace(/\s+/g,' ')).filter(Boolean)})
      }
    }
    ts.forEachChild(n,visit)
  }
  visit(src)
}
console.log('РОЗІРВАНИХ речень (≥2 кириличні текстові вузли в одного батька):',split.length)
for(const s of split) console.log(`\n${s.f}:${s.line}\n   ` + s.parts.map(p=>`«${p.slice(0,60)}»`).join('  +  '))
