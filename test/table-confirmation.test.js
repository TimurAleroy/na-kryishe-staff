'use strict';
// Focused UI contract test: real inline JS from the staff webapp, mocked HTTP only.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('index.html','utf8');

const scripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .map(m=>m[1]).filter(s=>s.trim());
test('all inline scripts retain valid JavaScript syntax',()=>{
  for(const s of scripts)new vm.Script(s);
  assert.ok(scripts.some(s=>s.length>100000));
});
function buildHarness(replies,agree=true) {
  const calls=[],prompts=[];
  const getPin=()=> 'dummy-test';
  const fetch=async(url,opts)=>{
    calls.push({url,payload:JSON.parse(opts.body)});
    const next=replies.shift();
    if(!next)throw new Error('Unexpected extra HTTP request');
    return {status:next.status,ok:next.status>=200&&next.status<300,
      json:async()=>next.body};
  };
  const askConfirm=async(text,opts)=>{prompts.push(text);return agree};
  const a=html.indexOf('  async function sendBookingWithTableConfirmation(');
  const b=html.indexOf('\n  async function submitAddBooking()',a);
  assert.ok(a>=0&&b>a,'Expected helper in published index.html');
  const code=html.slice(a,b);
  const fn=new Function('PROXY_BASE','getPin','fetch','askConfirm',
    code+'\nreturn sendBookingWithTableConfirmation;')('http://localhost:9876',getPin,fetch,askConfirm);
  return {fn,calls,prompts};
}
test('server 409 triggers one explicit confirm then force retry', async()=>{
  const h=buildHarness([
    {status:409,body:{needConfirm:true,error:'Стол занят другой бронью'}},
    {status:200,body:{ok:true,entry:'test'}}
  ]);
  const r=await h.fn('/api/staff/bookings/add',{name:'Гость'},'Создать');
  assert.equal(r.res.status,200);
  assert.equal(r.confirmed,true);
  assert.equal(h.calls.length,2);
  assert.equal(h.calls[0].payload.force,false);
  assert.equal(h.calls[1].payload.force,true);
  assert.equal(h.prompts.length,1);
  assert.match(h.prompts[0],/занят другой бронью/);
});
test('declined conflict leaves database request unconfirmed',async()=>{
  const h=buildHarness([{status:409,body:{needConfirm:true,error:'Накладка'}}],false);
  const r=await h.fn('/api/staff/bookings/table',{entry:'some'},'Назначить');
  assert.equal(r.cancelled,true);
  assert.equal(h.calls.length,1);
  assert.equal(h.calls[0].payload.force,false);
});
test('free table sends one request with force=false',async()=>{
  const h=buildHarness([{status:200,body:{ok:true}}]);
  const r=await h.fn('/api/staff/bookings/table',{entry:'some'},'Назначить');
  assert.equal(r.res.status,200);
  assert.equal(r.confirmed,false);
  assert.equal(h.calls.length,1);
  assert.equal(h.calls[0].payload.force,false);
  assert.equal(h.prompts.length,0);
});
test('second 409 is not retried infinitely',async()=>{
  const h=buildHarness([
    {status:409,body:{needConfirm:true,error:'Стол занят'}},
    {status:409,body:{needConfirm:true,error:'Стол занят снова'}}
  ]);
  const r=await h.fn('/api/staff/bookings/edit',{entry:'some'},'Перенести');
  assert.equal(r.res.status,409);
  assert.equal(h.calls.length,2);
});
test('the three user flows all use server-side confirmation',()=>{
  const paths=[
    "sendBookingWithTableConfirmation('/api/staff/bookings/add'",
    "sendBookingWithTableConfirmation('/api/staff/bookings/table'",
    "sendBookingWithTableConfirmation('/api/staff/bookings/edit'"
  ];
  for(const p of paths)assert.ok(html.includes(p),p+' missing');
});
