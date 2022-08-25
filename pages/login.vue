<template>
  <div>
    <button v-on:click="cryptrLogin()" class="bg-green-500 hover:bg-green-400 text-white font-bold py-2 px-4 rounded">
      Login Cryptr
    </button>
    <button v-on:click="checkUser()" class="bg-green-500 hover:bg-green-400 text-white font-bold py-2 px-4 rounded">
      check user
    </button>
    <button v-on:click="refresh()" class="bg-green-500 hover:bg-green-400 text-white font-bold py-2 px-4 rounded">
      Refresh
    </button>
  </div>
</template>

<script>
  const idpIds = "johns_moore_and_kihn_EVxTVHtTS8fR3SGoCux2yh,idkids_wJWKrT4bBD2NQKiJ9jzzRf,blockpulse_6Jc3TGatGmsHzexaRP5ZrE,shark_academy_qP7AXxnrPrf7CwWJgRhogj".split(',')

  export default {
    data() {
      return {
        login: {
          username: '',
          password: ''
        }
      }
    },
    methods: {
      async cryptrLogin() {
        try {
          // let response = await this.$auth.loginWith('cryptr', {data: {idpIds: idpIds}})
          let response = await this.$auth.loginWith('cryptr')
          console.log(response)
        } catch (error) {
          console.log('cryptr error', error)
        }
      },
      async checkUser() {
        console.log('user', this.$auth.user);
        console.log('loggedIn', this.$auth.loggedIn);
      },

      async refresh() {
        try {
          let response = await this.$auth.refreshTokens()
          console.log(response)
        } catch (error) {
          console.log('cryptr error', error)
        }
      }
    }
  }
</script>
