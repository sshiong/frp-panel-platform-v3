import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { ElDialog } from 'element-plus/es/components/dialog/index'
import 'element-plus/es/components/dialog/style/css'
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/message-box/style/css'
import './style.css'
import './domain.css'
import App from './App.vue'
createApp(App)
  .use(createPinia())
  .use(ElDialog)
  .mount('#app')
