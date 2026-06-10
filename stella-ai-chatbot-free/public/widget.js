(function(){
  var script=document.currentScript;if(!script)return;
  var apiBase=script.getAttribute('data-api-base')||new URL(script.src).origin;
  var css=document.createElement('link');css.rel='stylesheet';css.href=apiBase+'/widget.css';document.head.appendChild(css);
  function e(t){return String(t||'').replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c];});}
  function abs(u){u=String(u||'').trim();if(!u)return'';if(/^https?:\/\//i.test(u)||/^data:/i.test(u))return u;try{return new URL(u,apiBase+'/').toString()}catch(_){return u}}
  function q(s,r){return (r||document).querySelector(s)}
  function key(){var k=localStorage.getItem('stella_session_key');if(!k){k=(self.crypto&&crypto.randomUUID)?crypto.randomUUID():Date.now()+'-'+Math.random().toString(16).slice(2);localStorage.setItem('stella_session_key',k)}return k}
  function leadStateKey(){return 'stella_lead_saved_'+key()}
  function hasLead(){return localStorage.getItem(leadStateKey())==='1'}
  fetch(apiBase+'/api/config').then(function(r){return r.json()}).then(function(p){
    if(!p.success||!p.data.showWidget)return;var c=p.data;
    var pos=c.widgetPosition||'right';
    var w=document.createElement('div');
    w.className='stella-cb-widget stella-cb-'+pos;
    w.style.cssText='visibility:hidden;position:fixed;z-index:999999;bottom:24px;'+(pos==='left'?'left:24px':'right:24px');
    w.innerHTML='<button class="stella-cb-toggle" style="position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;border:none;background:white;padding:0;cursor:pointer;"><svg style="width:28px;height:28px;fill:white;" viewBox="0 0 24 24"><path d="M20,2H4C2.9,2,2,2.9,2,4v18l4-4h14c1.1,0,2-0.9,2-2V4C22,2.9,21.1,2,20,2z M20,16H5.2L4,17.2V4h16V16z M7,9h10v2H7V9z M7,6h10v2H7V6z M7,12h7v2H7V12z"/></svg><img alt="chat" style="display:none;position:absolute;top:0;left:0;width:100%;height:100%;object-fit:cover;border-radius:inherit;"></button><div class="stella-cb-panel"><div class="stella-cb-header"><strong>'+e(c.chatbotName||'Stella Assistant')+'</strong><button class="stella-cb-close" title="Close">&times;</button></div><div class="stella-cb-messages"></div><div class="stella-cb-input-wrap"><input type="text" placeholder="Type a message..."><button class="stella-cb-send-btn">Send</button></div>'+(c.creditEnabled?('<div class="stella-cb-credit"><a target="_blank" rel="noopener noreferrer" href="'+e(c.creditUrl)+'">'+e(c.creditText)+'</a></div>'):'')+'</div>';
    document.body.appendChild(w);
    var t=q('.stella-cb-toggle',w), img=q('img',t), svg=q('svg',t), panel=q('.stella-cb-panel',w), close=q('.stella-cb-close',w), msgs=q('.stella-cb-messages',w), input=q('input',w), send=q('.stella-cb-send-btn',w);
    if(c.avatarUrl){img.src=abs(c.avatarUrl); img.style.display='block'; svg.style.display='none';} else {svg.style.display='block';}
    var sz=Number(c.widgetSize||56); t.style.width=sz+'px'; t.style.height=sz+'px';
    var anim=String(c.widgetAnimation||'float').toLowerCase(); if(anim!=='none') t.classList.add('anim-'+anim);
    t.style.borderRadius=(c.avatarShape==='square'?'10px':(c.avatarShape==='rounded'?'18px':'50%'));
    panel.style.width=Number(c.chatboxWidth||380)+'px'; panel.style.height=Number(c.chatboxHeight||520)+'px';
    if(c.chatboxBgColor) msgs.style.background=c.chatboxBgColor;
    if(c.brandColor) w.style.setProperty('--stella-brand', c.brandColor);
    panel.style.display='none'; w.style.visibility='visible';
    var widgetAuthToken=String(c.widgetAuthToken||'');
    var selectedCategory=''; var categories=((c.welcomeCategories&&c.welcomeCategories.length)?c.welcomeCategories:c.allCategories||[]).slice(); var page=0; var faqPage=0; var welcomeShown=false;
    function add(html,cls){
      var d=document.createElement('div');
      d.className='stella-cb-msg '+(cls||'bot');
      d.innerHTML=html;
      msgs.appendChild(d);
      if((cls||'bot')==='bot'){
        try{d.scrollIntoView({block:'start',behavior:'smooth'});}catch(_){msgs.scrollTop=d.offsetTop}
      } else {
        msgs.scrollTop=msgs.scrollHeight;
      }
    }
    function catView(pn){if(!c.showWelcomeCategories||!categories.length)return;var size=3,max=Math.max(0,Math.ceil(categories.length/size)-1);page=Math.max(0,Math.min(pn,max));var st=page*size,arr=categories.slice(st,st+size);var h='<div style="margin-bottom:8px; font-weight:500;">Choose a category:</div><div style="display:flex; flex-wrap:wrap; gap:4px;">';arr.forEach(function(x){h+='<button class="stella-cb-suggest cat" data-cat="'+e(x)+'">'+e(x)+'</button>'});h+='</div><div style="margin-top:8px;">';if(page>0)h+='<button class="stella-cb-suggest cat-back">Back</button>';if(page<max)h+='<button class="stella-cb-suggest cat-more">More</button>';h+='</div>';add(h,'bot')}
    function catFaqView(pn){
      var source=((c.faqByCategory&&c.faqByCategory[selectedCategory])||[]);
      var size=3,max=Math.max(0,Math.ceil(source.length/size)-1);
      faqPage=Math.max(0,Math.min(pn,max));
      var st=faqPage*size,arr=source.slice(st,st+size);
      var h='<div style="margin-bottom:8px;">Selected category: <strong>'+e(selectedCategory)+'</strong></div>';
      if(arr.length){
        h+='<div style="margin-top:6px; margin-bottom:8px; font-weight:500;">Try one of these:</div><div style="display:flex; flex-wrap:wrap; gap:4px;">';
        arr.forEach(function(item){h+='<button class="stella-cb-suggest key" data-key="'+e(item.keyword)+'">'+e(item.question)+'</button>'});
        h+='</div>';
      } else {
        h+='<div style="margin-top:6px; color:var(--stella-muted);">Now type your question.</div>';
      }
      h+='<div style="margin-top:12px; display:flex; flex-wrap:wrap; gap:4px;">';
      if(faqPage>0)h+='<button class="stella-cb-suggest q-back">Back</button>';
      if(faqPage<max)h+='<button class="stella-cb-suggest q-more">More</button>';
      h+='<button class="stella-cb-suggest back">Back to categories</button></div>';
      add(h,'bot');
    }
    function showLeadCapture(){
      if(!c.leadCaptureEnabled||hasLead()) return;
      if(msgs.querySelector('.lead-save')) return;
      var h='<div style="margin-bottom:12px; font-weight:500;">'+e(c.leadCapturePrompt||'Before we continue, please share your name and email.')+'</div><div class="stella-cb-lead"><input type="text" class="lead-name" placeholder="Your name"><input type="email" class="lead-email" placeholder="Your email"><button class="lead-save">Continue</button></div>';
      add(h,'bot');
    }
    function showWelcome(){
      if(welcomeShown)return;
      welcomeShown=true;
      if(c.showWelcomeMessage&&c.welcomeMessage)add(e(c.welcomeMessage).replace(/\n/g,'<br>'),'bot');
      if(c.leadCaptureEnabled&&!hasLead()){
        showLeadCapture();
        return;
      }
      catView(0);
    }
    function sendMsg(v){var text=String(v||input.value||'').trim();if(!text)return;if(c.leadCaptureEnabled&&!hasLead()){add('Please share your name and email first.','bot');showLeadCapture();return;}add(e(text),'user');input.value='';var load=document.createElement('div');load.className='stella-cb-msg bot';load.innerHTML='<span style="display:inline-block; animation:pulse 1s infinite;">Thinking...</span>';msgs.appendChild(load);msgs.scrollTop=msgs.scrollHeight;
      fetch(apiBase+'/api/chat/query',{method:'POST',headers:{'Content-Type':'application/json','X-Stella-Widget-Auth':widgetAuthToken},body:JSON.stringify({sessionKey:key(),message:text,selectedCategory:selectedCategory,pageUrl:location.href})}).then(function(r){return r.json()}).then(function(r){load.remove();if(!r.success){add('Error processing message.','bot');return;}var d=r.data||{};var out=d.answerHtml||'';if(c.showReturnToCategoriesLink)out+='<div style="margin-top:12px;"><button class="stella-cb-suggest back">Back to categories</button></div>';if(d.source==='ai'&&d.aiDisclaimer)out+='<div class="stella-cb-ai-disclaimer">'+e(d.aiDisclaimer).replace(/\n/g,'<br>')+'</div>';add(out,'bot'); if(d.suggestions&&d.suggestions.length){ var sugH='<div style="margin-top:10px; display:flex; flex-wrap:wrap; gap:4px;">'; d.suggestions.slice(0,3).forEach(function(s){sugH+='<button class="stella-cb-suggest key" data-key="'+e(s.keyword)+'">'+e(s.question)+'</button>'}); sugH+='</div>'; add(sugH,'bot'); } if(d.handoff&&d.handoff.message){var h=e(d.handoff.message);if(d.handoff.url)h+=' <a target="_blank" rel="noopener noreferrer" href="'+e(d.handoff.url)+'">Contact support</a>';add(h,'bot')}}).catch(function(){load.remove();add('Unable to connect.','bot')})
    }

    t.onclick=function(){var isOpen=panel.style.display!=='none';panel.style.display=isOpen?'none':'flex';if(!isOpen)showWelcome()}; close.onclick=function(){panel.style.display='none'}; send.onclick=function(){sendMsg()}; input.addEventListener('keydown',function(ev){if(ev.key==='Enter'){ev.preventDefault();sendMsg()}});
    msgs.addEventListener('click',function(ev){
      var el=ev.target;if(!(el instanceof HTMLElement))return;
      if(el.classList.contains('cat')){
        selectedCategory=el.getAttribute('data-cat')||'';
        catFaqView(0);
        return;
      }
      if(el.classList.contains('lead-save')){
        var wrap=el.closest('.stella-cb-lead'); if(!wrap) return;
        var n=wrap.querySelector('.lead-name'); var em=wrap.querySelector('.lead-email');
        var name=String((n&&n.value)||'').trim(); var email=String((em&&em.value)||'').trim();
        if(!name||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){add('Please enter a valid name and email.','bot');return;}
        fetch(apiBase+'/api/chat/lead',{method:'POST',headers:{'Content-Type':'application/json','X-Stella-Widget-Auth':widgetAuthToken},body:JSON.stringify({sessionKey:key(),name:name,email:email})}).then(function(r){return r.json()}).then(function(r){if(r&&r.success){localStorage.setItem(leadStateKey(),'1');add('Thanks. Details saved. You can continue chatting.','bot');catView(0);}else{add('Could not save details. Please try again.','bot');}}).catch(function(){add('Could not save details. Please try again.','bot')});
        return;
      }
      if(el.classList.contains('cat-more')){catView(page+1);return;}
      if(el.classList.contains('cat-back')){catView(page-1);return;}
      if(el.classList.contains('q-more')){catFaqView(faqPage+1);return;}
      if(el.classList.contains('q-back')){catFaqView(faqPage-1);return;}
      if(el.classList.contains('back')){catView(0);return;}
      if(el.classList.contains('key')){sendMsg(el.getAttribute('data-key')||'');return;}
    });
  }).catch(function(){});
})();
