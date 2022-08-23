<template>
  <div>
    <form @submit.prevent="userLogin">
      <div>
        <label>Username</label>
        <input type="text" v-model="login.username" />
      </div>
      <div>
        <label>Password</label>
        <input type="text" v-model="login.password" />
      </div>
      <div>
        <button type="submit">Submit</button>
      </div>
    </form>
    <hr class="my-4"/>
    <button v-on:click="googleLogin()" class="bg-blue-500 hover:bg-blue-400 text-white font-bold py-2 px-4 rounded">
      Login google
    </button>
    <button v-on:click="auth0Login()" class="bg-red-500 hover:bg-red-400 text-white font-bold py-2 px-4 rounded">
      Login auth0
    </button>
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
      async userLogin() {
        try {
          let response = await this.$auth.loginWith('local', { data: this.login })
          console.log(response)
        } catch (err) {
          console.log(err)
        }
      },
      async googleLogin() {
        try {
          let response = await this.$auth.loginWith('google')
          console.log(response)
        } catch (error) {
          console.log('google error', error)
        }
      },
      async auth0Login() {
        try {
          let response = await this.$auth.loginWith('auth0')
          console.log(response)
        } catch (error) {
          console.log('auth0 error', error)
        }
      },
      async cryptrLogin() {
        try {
          let response = await this.$auth.loginWith('cryptr')
          console.log(response)
        } catch (error) {
          console.log('auth0 error', error)
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
          console.log('auth0 error', error)
        }
      }
    }
  }
</script>
