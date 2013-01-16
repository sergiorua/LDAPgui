var FadeElement="";var FadeOpacity=0;var FadeEffect=true;var FadeDelay=60;function fadeIn(){if(FadeOpacity<101){FadeElement.style.MozOpacity=""+(FadeOpacity/100);FadeElement.style.opacity=""+(FadeOpacity/100);FadeElement.style.filter='alpha(opacity='+FadeOpacity+')';FadeOpacity+=10;setTimeout('fadeIn()',FadeDelay);}}
function fadeOut(){if(FadeOpacity>1){FadeElement.style.MozOpacity=""+(FadeOpacity/100);FadeElement.style.opacity=""+(FadeOpacity/100);FadeElement.style.filter='alpha(opacity='+FadeOpacity+')';FadeOpacity-=10;setTimeout('fadeOut()',FadeDelay);}else{FadeElement.style.display='none';FadeElement.style.visibility='hidden';}}
function showDiv(d){FadeElement=document.getElementById(d);if(!FadeElement){alert("Cannot find element "+d);return(false);}
if(FadeEffect){FadeOpacity=1;FadeElement.style.MozOpacity=""+(FadeOpacity/100);FadeElement.style.opacity=""+(FadeOpacity/100);FadeElement.style.filter='alpha(opacity='+FadeOpacity+')';}
FadeElement.style.display='block';FadeElement.style.visibility='visible';if(FadeEffect)fadeIn();}
function hideDiv(d){FadeElement=document.getElementById(d);if(!FadeElement){alert("Cannot find element "+d);return(false);}
if(FadeEffect){FadeOpacity=100;FadeElement.style.MozOpacity=""+(FadeOpacity/100);FadeElement.style.opacity=""+(FadeOpacity/100);FadeElement.style.filter='alpha(opacity='+FadeOpacity+')';fadeOut();}else{FadeElement.style.display='none';FadeElement.style.visibility='hidden';}}
function flashMsg(msg){var e=document.getElementById(e);if(!e)return(false);e.innerHTML=msg;return(true);}
var panes=new Array();function setupPanes(containerId,defaultTabId){panes[containerId]=new Array();var maxHeight=0;var maxWidth=0;var container=document.getElementById(containerId);var paneContainer=container.getElementsByTagName("div")[0];var paneList=paneContainer.childNodes;for(var i=0;i<paneList.length;i++){var pane=paneList[i];if(pane.nodeType!=1)continue;if(pane.offsetHeight>maxHeight)maxHeight=pane.offsetHeight;if(pane.offsetWidth>maxWidth)maxWidth=pane.offsetWidth;panes[containerId][pane.id]=pane;pane.style.display="none";}
paneContainer.style.height=maxHeight+"px";paneContainer.style.width=maxWidth+"px";document.getElementById(defaultTabId).onclick();}
function showPane(paneId,activeTab){for(var con in panes){activeTab.blur();activeTab.className="tab-active";if(panes[con][paneId]!=null){var pane=document.getElementById(paneId);pane.style.display="block";var container=document.getElementById(con);var tabs=container.getElementsByTagName("ul")[0];var tabList=tabs.getElementsByTagName("a")
for(var i=0;i<tabList.length;i++){var tab=tabList[i];if(tab!=activeTab)tab.className="tab-disabled";}
for(var i in panes[con]){var pane=panes[con][i];if(pane==undefined)continue;if(pane.id==paneId)continue;pane.style.display="none"}}}
return false;}
function myStickyTip(title,text,l){if(!l){if(text.length<100){l=100;}else{l=200;}}
return Tip(text,SHADOW,true,TITLEALIGN,'center',SHADOWWIDTH,7,FADEIN,1000,FADEOUT,1000,CLOSEBTN,true,CLOSEBTNCOLORS,['','#66ff66','white','#00cc00'],STICKY,true,DELAY,0,WIDTH,200,DURATION,10000,TITLE,title);}
function myTip(title,text,l){if(!l){if(text.length<100){l=100;}else{l=200;}}
return Tip(text,SHADOW,true,TITLEALIGN,'center',DELAY,1000,SHADOWWIDTH,7,WIDTH,l,TITLE,title);}
function myInfoTip(n){if(n.length<100){l=100;}else{l=200;}
return Tip(n,SHADOW,true,TITLEALIGN,'center',WIDTH,l,TITLEFONTSIZE,'9px',FIX,[100,400],FADEIN,1000,FADEOUT,1000,CLOSEBTN,true,CLOSEBTNCOLORS,['','#66ff66','white','#00cc00'],SHADOWWIDTH,7,TITLE,'IT Projections');}
