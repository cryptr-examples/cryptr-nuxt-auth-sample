<template>
  <div>
    <div class="grid gap-2 grid-cols-4 mx-auto-items-center">
      <button v-on:click="cryptrLogin({type: 'signin'})" v-if="!$auth.loggedIn" class="bg-gray-500 hover:bg-gray-400 text-white font-bold py-2 px-4 rounded">
        Magic link
      </button>
      <button v-on:click="cryptrLogin({type: 'sso'})" v-if="!$auth.loggedIn" class="bg-blue-500 hover:bg-blue-400 text-white font-bold py-2 px-4 rounded">
        SSO Bare Gateway
      </button>
      <button v-on:click="cryptrLogin({type: 'sso', idpIds: idpIds})" v-if="!$auth.loggedIn" class="bg-blue-500 hover:bg-blue-400 text-white font-bold py-2 px-4 rounded">
        Multi SSO Gateway
      </button>
      <button v-on:click="cryptrLogin({type: 'sso', idpIds: idpIds, locale: 'fr'})" v-if="!$auth.loggedIn" class="bg-blue-500 hover:bg-blue-400 text-white font-bold py-2 px-4 rounded">
        Portail SSO
      </button>
    </div>
    <hr class="divider my-2" />
    <div class="grid gap-4 grid-cols-2 mx-auto-items-center">
      <button v-on:click="checkUser()" class="bg-yellow-500 hover:bg-yellow-400 text-white font-bold py-2 px-4 rounded">
        check user
      </button>
      <button v-on:click="checkVuexState()" class="bg-purple-500 hover:bg-purple-400 text-white font-bold py-2 px-4 rounded">
        check vuex state
      </button>
    </div>
    <div class="grid gap-4 grid-cols-4 mx-auto-items-center my-2">
      <button v-on:click="refresh()" v-if="$auth.loggedIn" class="bg-green-500 hover:bg-green-400 text-white font-bold py-2 px-4 rounded">
        Refresh
      </button>
    </div>
    <div v-if="$auth.loggedIn" class="bg-indigo-100 border-t-4 border-indigo-500 rounded-b text-indigo-900 px-4 py-3 shadow-md mt-6" role="alert">
      <div class="flex">
        <div class="py-1"><svg class="fill-current h-6 w-6 text-indigo-500 mr-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M2.93 17.07A10 10 0 1 1 17.07 2.93 10 10 0 0 1 2.93 17.07zm12.73-1.41A8 8 0 1 0 4.34 4.34a8 8 0 0 0 11.32 11.32zM9 11V9h2v6H9v-4zm0-6h2v2H9V5z"/></svg></div>
        <div>
          <p class="font-bold">User Info</p>
          <pre class="rounded border border-indigo-700">
            <code>
              {{$auth.user}}
            </code>
          </pre>
        </div>
      </div>
    </div>
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
        },
        idpIds: idpIds
      }
    },
    methods: {
      async cryptrLogin(attrs) {
        try {
          let response = await this.$auth.loginWith('cryptr', {attrs: attrs})
          console.log(response)
        } catch (error) {
          console.log('cryptr error', error)
        }
      },
      async checkUser() {
        console.log('user', this.$auth.user);
        console.log('loggedIn', this.$auth.loggedIn);
      },
      async checkVuexState() {
        console.debug('vuex state', this.$store.state.auth)
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
