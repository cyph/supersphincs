(function () {


var isNode	= false;
if (typeof module !== 'undefined' && module.exports) {
	isNode	= true;
}


var superSphincs = (function () {

if (isNode) {
	self	= this;
}
