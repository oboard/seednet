---
layout: home
---

<script setup>
import { useRouter } from 'vitepress'
import { onMounted } from 'vue'

const router = useRouter()
onMounted(() => {
  const lang = navigator.language || 'en'
  if (lang.startsWith('zh')) {
    router.go('/zh/')
  } else {
    router.go('/en/')
  }
})
</script>
