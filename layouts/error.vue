<template>
  <div>
    <h1>An error occurred</h1>
    <p>{{error.statusCode}}</p>
    <NuxtLink to="/">Home page</NuxtLink>
  </div>
</template>

<script>
export default {
  props: ['error'],
  layout: 'error' // you can set a custom layout for the error page
}
</script>

