<template>
  <div>
    <NuxtLink to="/private" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded text-center w-full">
    Go to private
    </NuxtLink>
  </div>
</template>

<script lang="ts">
import NuxtLogo from "./NuxtLogo.vue";


export default {
    name: "Home",
    components: { NuxtLogo }
}
</script>

