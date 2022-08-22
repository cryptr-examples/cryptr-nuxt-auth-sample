<template>
  <div class="grid gap-4 mx-auto my-auto items-center">
    <h1 class="text-5xl">This is a private page</h1>
    <NuxtLink to="/" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded text-center w-full">Go back to Home</NuxtLink>
  </div>
</template>

<script lang="ts">
import Vue from 'vue'

export default Vue.extend({
  name: 'PrivatePage'
})
</script>
