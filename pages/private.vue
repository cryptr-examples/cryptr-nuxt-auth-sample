<template>
  <div class="mx-auto my-auto items-center">
    <h1 class="text-5xl mb-6 text-center">This is a private page</h1>
    <div class="grid gap-4 grid-cols-4 mx-auto my-auto items-center">
      <NuxtLink to="/" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded text-center w-full">Go back to Home</NuxtLink>
       <button v-on:click="checkUser()" class="bg-green-500 hover:bg-green-400 text-white font-bold py-2 px-4 rounded">
        check user
      </button>
      <button v-on:click="refresh()" class="bg-green-500 hover:bg-green-400 text-white font-bold py-2 px-4 rounded">
        Refresh
      </button>
      <button v-on:click="logOut()" class="bg-red-500 hover:bg-red-400 text-white font-bold py-2 px-4 rounded">
        Log out
      </button>
    </div>
  </div>
</template>

<script lang="ts">
import Vue from 'vue'

export default Vue.extend({
  name: 'PrivatePage',
  methods: {
    async checkUser() {
        console.log('user', this.$auth.user);
        console.log('loggedIn', this.$auth.loggedIn);
      },
      async refresh() {
        try {
          console.log('private refresh')
          let response = await this.$auth.refreshTokens()
          console.log(response)
        } catch (error) {
          console.log('cryptr error', error)
        }
      },
      async logOut() {
        try {
          let response = await this.$auth.logout()
          console.log(response)
        } catch (error) {
          console.log('cryptr error', error)
        }
      }
  }
})
</script>
