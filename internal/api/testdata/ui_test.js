const assert=require('assert');
// FIELDS 用运行中的服务真实返回的那份,而不是手写一份 —— 手写的迟早
// 与后端不同步,而 coerce 判类型完全依赖它。
global.FIELDS=require('./fields.json');
const {protoLabel,coerce,isIntField,pivot,localInput}=require('./ui.js');
let n=0; const t=(name,fn)=>{fn();n++;console.log('  ok',name)};

t('protoLabel 把数字换成名字',()=>{
  assert.strictEqual(protoLabel(6),'TCP');
  assert.strictEqual(protoLabel('17'),'UDP');
  assert.match(protoLabel(253),/253/);           // 未知协议要显示原值,不能变 undefined
});

t('coerce:整数字段必须是数字',()=>{
  assert.strictEqual(coerce('dst_port','22'),22);
  assert.strictEqual(coerce('src_asn','13335'),13335);
  assert.strictEqual(coerce('src_country','CN'),'CN');   // 字符串字段保持原样
  assert.ok(isIntField('dst_port') && !isIntField('src_ip'));
});

// pivot 是这次改动里最容易出错的一段:ECharts 堆叠按下标相加,
// 不按 x 值对齐。缺点的序列必须补 0,否则堆叠高度全错。
t('pivot 把缺失的时间点补 0',()=>{
  const rows=[[100,'a',10],[200,'a',20],[200,'b',5],[300,'b',7]];
  const s=pivot(rows,['a','b']);
  assert.strictEqual(s.length,2);
  const ts=s.map(x=>x.data.map(p=>p[0]));
  assert.deepStrictEqual(ts[0],ts[1],'两条序列的时间轴必须完全一致');
  assert.deepStrictEqual(ts[0],[100000,200000,300000],'时间要升序且换成毫秒');
  assert.deepStrictEqual(s[0].data.map(p=>p[1]),[10,20,0]);
  assert.deepStrictEqual(s[1].data.map(p=>p[1]),[0,5,7]);
});

t('pivot 时间乱序也要排好',()=>{
  const s=pivot([[300,'a',3],[100,'a',1],[200,'a',2]],['a']);
  assert.deepStrictEqual(s[0].data.map(p=>p[1]),[1,2,3]);
});

t('pivot 忽略不在 keys 里的行',()=>{
  const s=pivot([[100,'a',1],[100,'zzz',999]],['a']);
  assert.deepStrictEqual(s[0].data,[[100000,1]]);
});

t('pivot 空值显示成(未知)',()=>{
  assert.strictEqual(pivot([[100,'',1]],[''])[0].name,'(未知)');
  assert.strictEqual(pivot([[100,'6',1]],['6'],protoLabel)[0].name,'TCP');
});

// 直接切 ISO 字符串会把 UTC+8 的时间往前挪 8 小时,
// 表现为"选了自定义范围,图上的时间对不上"。
t('localInput 用本地时区',()=>{
  const d=new Date(2026,7,13,9,5,0);
  assert.strictEqual(localInput(d.toISOString()),'2026-08-13T09:05');
});

console.log(n+' 项通过');
