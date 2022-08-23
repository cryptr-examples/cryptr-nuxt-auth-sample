<template>
  <div class="grid gap-4 mx-auto my-auto items-center">
    <NuxtLink to="/private" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded text-center w-full mx-auto">
    Go to private
    </NuxtLink>
  </div>
</template>

<script lang="ts">
import CryptrLogo from "./CryptrLogo.vue";


export default {
    name: "Home",
    auth: false,
    components: { CryptrLogo }
}
</script>

