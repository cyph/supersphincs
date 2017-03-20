(function () {


var isNode	=
	typeof process === 'object' &&
	typeof require === 'function' &&
	typeof window !== 'object' &&
	typeof importScripts !== 'function'
;


var superSphincs = (function () {

if (isNode) {
	self	= this;
}
