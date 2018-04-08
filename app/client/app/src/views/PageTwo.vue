<template>
  <section>

    <div class="card">
      <header class="card-header">
        <p class="card-header-title">
          Генерация ключей
        </p>
      </header>

      <div class="card-content">
        <div class="content">

            <!-- SAMPLE BULMA FORM -->
            <div class="field">
              <label class="label">Master public key</label>
              <div class="field is-grouped">
                <p class="control is-expanded">
                  <input class="input" type="text" placeholder="Введите значение" ref="masterPublicKey">
                </p>
                <p class="control">
                  <a class="button is-info" @click.prevent="getChildKey()">
                    Сгенерировать адрес
                  </a>
                </p>
              </div>

                  {{ publicKey }}
              </div>
            </div>

            <div class="field">
                <label class="label">Seed</label>
                <div class="field is-grouped">
                    <p class="control is-expanded">
                        <input class="input" type="text" placeholder="Введите значение" ref="seed">
                    </p>
                    <p class="control">
                        <a class="button is-info" @click.prevent="getExtendedKeys()">
                            Получить расширенные ключи
                        </a>
                    </p>
                </div>
                <div class="box content is-info" v-if="extendedKeys">
                    {{extendedKeys}}
                </div>
            </div>
        </div>
      </div>


  </section>
</template>

<script>

export default {
  name: 'Page2',
  data () {
    return {
        title: 'Generate keys',
        extended_keys: {
            'ext_master_private_key': null,
            'ext_master_public_key': null
        }
    }
  },
  computed: {
    publicKey () {
        return this.$store.state.publicKey
    },
    extendedKeys () {
        return this.$store.state.extended_keys;
        // console.log(this.extended_keys);
        // console.log(ext_keys);
        // //if (ext_keys){
        // this.extended_keys = Object.assign({}, this.$store.state.extended_keys)
        //}
    }
  },


  methods: {
    getChildKey () {
      this.$store.dispatch('getPublicKey', this.$refs.masterPublicKey.value)
    },

    getExtendedKeys () {
      this.$store.dispatch('getExtendedKeys', this.$refs.seed.value)
    },
  },
  mounted () {
    // Do something
  }
}
</script>

<style lang="sass" scoped>

</style>
