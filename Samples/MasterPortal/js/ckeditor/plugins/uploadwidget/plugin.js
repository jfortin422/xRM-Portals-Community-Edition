﻿/*
 Copyright (c) 2003-2015, CKSource - Frederico Knabben. All rights reserved.
 This software is covered by CKEditor Commercial License. Usage without proper license is prohibited.
*/
(function(){CKEDITOR.plugins.add("uploadwidget",{lang:"cs,da,de,en,eo,fr,gl,hu,it,ko,ku,nb,nl,pl,pt-br,ru,sv,tr,zh,zh-cn",requires:"widget,clipboard,filetools,notificationaggregator",init:function(b){b.filter.allow("*[!data-widget,!data-cke-upload-id]")}});CKEDITOR.fileTools||(CKEDITOR.fileTools={});CKEDITOR.tools.extend(CKEDITOR.fileTools,{addUploadWidget:function(b,c,a){var f=CKEDITOR.fileTools,m=b.uploadRepository,p=a.supportedTypes?10:20;if(a.fileToElement)b.on("paste",function(k){k=k.data;var n=
k.dataTransfer,e=n.getFilesCount(),l=a.loadMethod||"loadAndUpload",d,g;if(!k.dataValue&&e)for(g=0;g<e;g++)if(d=n.getFile(g),!a.supportedTypes||f.isTypeSupported(d,a.supportedTypes)){var h=a.fileToElement(d);d=m.create(d);h&&(d[l](a.uploadUrl),CKEDITOR.fileTools.markElement(h,c,d.id),"loadAndUpload"!=l&&"upload"!=l||CKEDITOR.fileTools.bindNotifications(b,d),k.dataValue+=h.getOuterHtml())}},null,null,p);CKEDITOR.tools.extend(a,{downcast:function(){return new CKEDITOR.htmlParser.text("")},init:function(){var a=
this,c=this.wrapper.findOne("[data-cke-upload-id]").data("cke-upload-id"),e=m.loaders[c],f=CKEDITOR.tools.capitalize,d,g;e.on("update",function(h){if(a.wrapper&&a.wrapper.getParent()){b.fire("lockSnapshot");h="on"+f(e.status);if("function"!==typeof a[h]||!1!==a[h](e))g="cke_upload_"+e.status,a.wrapper&&g!=d&&(d&&a.wrapper.removeClass(d),a.wrapper.addClass(g),d=g),"error"!=e.status&&"abort"!=e.status||b.widgets.del(a);b.fire("unlockSnapshot")}else b.editable().find('[data-cke-upload-id\x3d"'+c+'"]').count()||
e.abort(),h.removeListener()});e.update()},replaceWith:function(a,c){if(""===a.trim())b.widgets.del(this);else{var e=this==b.widgets.focused,f=b.editable(),d=b.createRange(),g,h;e||(h=b.getSelection().createBookmarks());d.setStartBefore(this.wrapper);d.setEndAfter(this.wrapper);e&&(g=d.createBookmark());f.insertHtmlIntoRange(a,d,c);b.widgets.checkWidgets({initOnlyNew:!0});b.widgets.destroy(this,!0);e?(d.moveToBookmark(g),d.select()):b.getSelection().selectBookmarks(h)}}});b.widgets.add(c,a)},markElement:function(b,
c,a){b.setAttributes({"data-cke-upload-id":a,"data-widget":c})},bindNotifications:function(b,c){var a=b._.uploadWidgetNotificaionAggregator;if(!a||a.isFinished())a=b._.uploadWidgetNotificaionAggregator=new CKEDITOR.plugins.notificationAggregator(b,b.lang.uploadwidget.uploadMany,b.lang.uploadwidget.uploadOne),a.once("finished",function(){var c=a.getTaskCount();0===c?a.notification.hide():a.notification.update({message:1==c?b.lang.uploadwidget.doneOne:b.lang.uploadwidget.doneMany.replace("%1",c),type:"success",
important:1})});var f=a.createTask({weight:c.total});c.on("update",function(){f&&"uploading"==c.status&&f.update(c.uploaded)});c.on("uploaded",function(){f&&f.done()});c.on("error",function(){f&&f.cancel();b.showNotification(c.message,"warning")});c.on("abort",function(){f&&f.cancel();b.showNotification(b.lang.uploadwidget.abort,"info")})}})})();