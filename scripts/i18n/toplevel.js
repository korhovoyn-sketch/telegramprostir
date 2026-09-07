const ts=require('typescript'), fs=require('fs')
const {walkFiles}=require('./extract.js')
const hits=[]
for(const f of walkFiles('src')){
  const src=ts.createSourceFile(f,fs.readFileSync(f,'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX)
  const visit=(n,inFn)=>{
    const isFn = ts.isFunctionDeclaration(n)||ts.isFunctionExpression(n)||ts.isArrowFunction(n)||
                 ts.isMethodDeclaration(n)||ts.isGetAccessor(n)||ts.isClassDeclaration(n)
    if(ts.isCallExpression(n)&&ts.isIdentifier(n.expression)&&(n.expression.text==='tr'||n.expression.text==='tx')&&!inFn){
      // знайти найближчу оголошену змінну — саме її треба зробити лінивою
      let decl=null
      for(let a=n.parent;a;a=a.parent) if(ts.isVariableDeclaration(a)){decl=a.name.getText();break}
      hits.push({f,decl:decl??'(inline)'})
    }
    ts.forEachChild(n,c=>visit(c,inFn||isFn))
  }
  ts.forEachChild(src,c=>visit(c,false))
}
const byDecl={}
for(const h of hits){const k=`${h.f} → ${h.decl}`; byDecl[k]=(byDecl[k]||0)+1}
console.log('КОНСТАНТ, які треба зробити лінивими:',Object.keys(byDecl).length)
Object.entries(byDecl).sort((a,b)=>b[1]-a[1]).forEach(([k,n])=>console.log(`  ${String(n).padStart(3)}×  ${k}`))
