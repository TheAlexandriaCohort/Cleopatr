import * as cedar from '@cedar-policy/cedar-wasm/web';
import module from '../node_modules/@cedar-policy/cedar-wasm/web/cedar_wasm_bg.wasm?module';
cedar.initSync({ module });
export default cedar;
