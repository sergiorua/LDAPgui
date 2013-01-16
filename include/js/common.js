var included_files=new Array();function isArray(obj){if(obj.constructor.toString().indexOf("Array")==-1)
return false;else
return true;}
function include_dom(script_filename){var html_doc=document.getElementsByTagName('head').item(0);var js=document.createElement('script');js.setAttribute('language','javascript');js.setAttribute('type','text/javascript');js.setAttribute('src',script_filename);html_doc.appendChild(js);return false;}
function include_css(css_filename){var html_doc=document.getElementsByTagName('head').item(0);var css=document.createElement('link');css.setAttribute('href',css_filename);css.setAttribute('type','text/css');css.setAttribute('rel','stylesheet');html_doc.appendChild(css);return false;}
function include_once(script_filename){if(!in_array(script_filename,included_files)){included_files[included_files.length]=script_filename;include_dom(script_filename);}}
function in_array(needle,haystack){for(var i=0;i<haystack.length;i++){if(haystack[i]==needle){return true;}}
return false;}
function enable_google_maps(){include_once("http://maps.google.com/maps?file=api&v=2&key=ABQIAAAADU__ulhzrpsNxlsqSBSNrhRi_j0U6kJrkFvY4-OX2XYmEAa76BSH1hJM2KRRdifmSsbw9nIdf36MEQ");}
function enable_autocomplete(){include_css("/include/autosuggest/css/autosuggest_inquisitor.css");include_once("/include/autosuggest/js/bsn.AutoSuggest_2.1.3.js");}
function parseJSON(json){try{if(/^("(\\.|[^"\\\n\r])*?"|[,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t])+?$/.test(json)){var j=eval('('+json+')');return j;}}catch(e){}
throw new SyntaxError("parseJSON");}
function ajaxObject(url,callbackFunction){var that=this;this.updating=false;this.abort=function(){if(that.updating){that.updating=false;that.AJAX.abort();that.AJAX=null;}}
this.update=function(passData,postMethod){if(that.updating){return false;}
that.AJAX=null;if(window.XMLHttpRequest){that.AJAX=new XMLHttpRequest();}else{that.AJAX=new ActiveXObject("Microsoft.XMLHTTP");}
if(that.AJAX==null){return false;}else{that.AJAX.onreadystatechange=function(){if(that.AJAX.readyState==4){that.updating=false;that.callback(that.AJAX.responseText,that.AJAX.status,that.AJAX.responseXML);that.AJAX=null;}}
that.updating=new Date();if(/post/i.test(postMethod)){var uri=urlCall+'?'+that.updating.getTime();that.AJAX.open("POST",uri,true);that.AJAX.setRequestHeader("Content-type","application/x-www-form-urlencoded");that.AJAX.setRequestHeader("Content-Length",passData.length);that.AJAX.send(passData);}else{var uri=urlCall+'?'+passData;that.AJAX.open("GET",uri,true);that.AJAX.send(null);}
return true;}}
var urlCall=url;this.callback=callbackFunction||function(){};}
include_once("/include/js/effects.js");
