const ts=require('typescript'), fs=require('fs')
const {walkFiles}=require('./extract.js')
let hits=[]
for(const f of walkFiles('src')){
  const text=fs.readFileSync(f,'utf8')
  if(!/from '@\/lib\/i18n'/.test(text)) continue
  const src=ts.createSourceFile(f,text,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX)
  const visit=n=>{
    // локальні звʼязування з іменем t: змінна, параметр, деструктуризація
    if((ts.isVariableDeclaration(n)||ts.isParameter(n)||ts.isBindingElement(n))&&n.name&&ts.isIdentifier(n.name)&&n.name.text==='tr'){
      if(!ts.isImportDeclaration(n.parent?.parent?.parent||{kind:0})){
        const {line}=src.getLineAndCharacterOfPosition(n.getStart())
        hits.push(`${f}:${line+1}  ${n.getText().slice(0,60)}`)
      }
    }
    ts.forEachChild(n,visit)
  }
  visit(src)
}
console.log('ЗАТІНЕНЬ імпортованого tr():',hits.length)
hits.forEach(h=>console.log('  ',h))
