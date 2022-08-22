import { mount } from '@vue/test-utils'
import CryptrLogo from '@/components/CryptrLogo.vue'

describe('CryptrLogo', () => {
  test('is a Vue instance', () => {
    const wrapper = mount(CryptrLogo)
    expect(wrapper.vm).toBeTruthy()
  })
})
