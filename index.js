// Cloudflare Pages 入口文件
import { handleRequest } from './functions.js';

export default {
  async fetch(request, env, ctx) {
    // 全局兜底异常捕获，彻底杜绝1101报错
    try {
      return await handleRequest(request);
    } catch (globalError) {
      return new Response(`❌ 系统错误：${globalError.message}`, {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }
  }
};