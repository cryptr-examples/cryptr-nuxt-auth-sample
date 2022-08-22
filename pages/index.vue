<template>
  <Home/>
</template>

<script lang="ts">
import Vue from 'vue'
import CryptrLogo from '~/components/CryptrLogo.vue';
import Home from '../components/Home.vue';

export default Vue.extend({
    name: "IndexPage",
    components: { CryptrLogo, Home }
})
</script>
