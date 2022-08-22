<template>
  <Home/>
</template>

<script lang="ts">
import Vue from 'vue'
import NuxtLogo from '~/components/NuxtLogo.vue';
import Home from '../components/Home.vue';

export default Vue.extend({
    name: "IndexPage",
    components: { NuxtLogo, Home }
})
</script>
