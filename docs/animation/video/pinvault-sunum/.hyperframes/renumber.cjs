// Renumber footer counters ("NN • TOTAL") and part labels for every frame in .hyperframes/order.json.
const fs=require('fs');
const order=JSON.parse(fs.readFileSync('.hyperframes/order.json','utf8'));const T=order.length;
const pad=n=>String(n).padStart(2,'0');
const part=i=>{const n=i+1;return n<=5?'PINVAULT · 1 AMAÇ':n<=8?'PINVAULT · 2 ÇÖZÜM':n<=23?'PINVAULT · 3 AKIŞ':n<=29?'PINVAULT · 4 DOSYALAR':'PINVAULT · ÖZET';};
order.forEach((id,i)=>{
  const f='compositions/frames/'+id+'.html';let s=fs.readFileSync(f,'utf8');const o=s;
  if(!id.match(/^p\d-bolum/)) s=s.replace(/PINVAULT · (1 AMAÇ|2 ÇÖZÜM|3 AKIŞ|4 DOSYALAR|ÖZET)/g,part(i));
  const A=/>(\d\d)<([^\n]{0,260}?)>(\d\d)</g, B=/(\d\d) • (\d\d)/g;
  let last=null,m;while((m=A.exec(s)))last={re:'A',idx:m.index,len:m[0].length,g:m};
  let lastB=null;while((m=B.exec(s)))lastB={idx:m.index,len:m[0].length};
  if(last&&(!lastB||last.idx>lastB.idx)){const g=last.g;s=s.slice(0,last.idx)+'>'+pad(i+1)+'<'+g[2]+'>'+T+'<'+s.slice(last.idx+last.len);}
  else if(lastB){s=s.slice(0,lastB.idx)+pad(i+1)+' • '+T+s.slice(lastB.idx+lastB.len);}
  else {console.log('NO COUNTER',id);}
  if(s!==o)fs.writeFileSync(f,s);
  const c=(s.match(/>(\d\d)<[^\n]{0,260}?>(\d\d)</g)||s.match(/\d\d • \d\d/g)||[]).slice(-1)[0];
  console.log(pad(i+1),id.padEnd(22),(c||'').replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').slice(0,40));
});
