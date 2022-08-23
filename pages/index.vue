<template>
  <div>
    <Home/>
  </div>
</template>

<script lang="ts">
import Vue from 'vue'
import CryptrLogo from '~/components/CryptrLogo.vue';
import Home from '../components/Home.vue';

export default Vue.extend({
    name: "IndexPage",
    auth: false,
    components: { CryptrLogo, Home },
     methods: {
      async auth0Login() {
        try {
          let response = await this.$auth.loginWith('auth0')
          console.log(response)
        } catch (error) {
          console.log('auth0 error', error)
        }
      },
    }
})
</script>
