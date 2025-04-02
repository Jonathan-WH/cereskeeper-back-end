import os
import requests

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def analyze_plant_gpt(image_urls, environment, variety, symptoms):
    image_data = [{"type": "image_url", "image_url": {"url": url}} for url in image_urls]

    messages = [
      {"role": "user", "content": [
        {"type": "text", "text": f"""
        You are an experienced horticulturist.
        Analyze the following images to detect any potential issues with the plant.
        • Environment: {environment}
        • Variety: {variety}
        • Observed symptoms: {symptoms}

        If a problem is detected, provide a clear response with:
        • 📌 Name of the issue
        • 🛠 Detailed explanation of the problem and its causes
        • 🚨 Possible consequences if left untreated
        • 🏡 100% organic and biological solution
        • 🧪 Chemical solution
        • 🌿 Hybrid solution (organic + chemical)

        If no issue is detected, simply respond: "No problems detected. Try a new analysis with different photos."

        📌 **Response Format (Important!)**:
        - Provide the answer **strictly in valid Ionic HTML format** using `<ion-card>`, `<ion-card-header>`, `<ion-card-title>`, and `<ion-card-content>`.
        - Do **not** include explanations outside of this structure.
        📌 **Response Format (Important!):**
        - **Do not use Markdown. Do not format text with `**bold**`. Provide plain HTML only.**
        - Example response format:
        
        ```html
        <ion-card color="success" mode="ios">
            <ion-card-header>
                <ion-card-title>Plant Analysis Result</ion-card-title>
                <ion-card-subtitle>Healthy Plant</ion-card-subtitle>
            </ion-card-header>
            <ion-card-content>
                No problems detected. Try a new analysis with different photos.
            </ion-card-content>
        </ion-card>

       <ion-card color="danger" class="card-analyse" mode="ios">
    <ion-card-header>
      <ion-card-title class="ion-text-center orbitron_medium">
        Detected Issue: Rust Disease
      </ion-card-title>
      <ion-card-subtitle class="ion-text-center subtile-analyse orbitron_medium">
        Fungal Disease
      </ion-card-subtitle>
    </ion-card-header>

    <ion-card-content>
      <ion-list>
        <!-- Description du problème -->
        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold"> What is Rust Disease?</h2>
            <p class="white">
              Rust disease is a fungal infection caused by various species of fungi from the Pucciniales order. 
              It manifests as small, yellow-orange pustules on the undersides of leaves, which later turn brown and release powdery spores. 
              The disease thrives in warm, humid conditions and spreads rapidly through windborne spores that can infect healthy plants. 
              It primarily affects cereal crops, ornamental plants, and some vegetables, reducing their photosynthesis capacity and overall health.
            </p>
          </ion-label>
        </ion-item>

        <!-- Conséquences -->
        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Consequences</h2>
            <p class="white">
              If left untreated, rust disease can cause severe defoliation, weakening the plant and making it more susceptible to secondary infections and environmental stress. 
              Affected plants experience reduced photosynthesis, leading to slower growth, lower crop yields, and, in extreme cases, plant death. 
              In agricultural settings, rust infections can result in significant economic losses, particularly in wheat, coffee, and soybean production. 
              The disease can also spread between different plant species, making containment and management crucial for plant health.
            </p>
          </ion-label>
        </ion-item>

        <!-- Solutions -->
        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Organic Solution</h2>
            <p class="white">
              The most effective organic approach involves **early detection** and **preventive action**. 
              Remove and destroy infected leaves immediately to prevent further spore dispersal.<br>
              Apply a **neem oil spray** or a **baking soda solution (1 tsp per liter of water)**, which alters the leaf surface pH and inhibits fungal growth.<br>
              Use a **garlic or horsetail tea spray**, known for their natural antifungal properties.<br>
              Improve plant spacing and air circulation to reduce humidity and fungal spread.<br>
              Enhance soil health by adding **compost tea or seaweed extracts**, which boost plant immunity.
            </p>
          </ion-label>
        </ion-item>

        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Chemical Solution</h2>
            <p class="white">
              Use a **fungicide containing myclobutanil, propiconazole, or tebuconazole**, as these are highly effective against rust fungi.<br>
              Follow manufacturer guidelines strictly, as overuse can lead to **fungal resistance**.<br>
              Apply the fungicide in **early morning or late evening** to prevent leaf burn and maximize absorption.<br>
              Rotate between different fungicide classes to prevent the fungi from developing resistance.
            </p>
          </ion-label>
        </ion-item>

        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Hybrid Solution</h2>
            <p class="white">
              Begin treatment with **neem oil** or **baking soda spray** for mild infections.<br>
              If the infection progresses, alternate between a **low-toxicity fungicide (copper-based)** and an organic spray to minimize chemical dependency.<br>
              Combine soil amendment strategies like **adding beneficial microbes (mycorrhizae, Trichoderma)** to boost plant defenses.<br>
              Adjust watering schedules to **morning hours only**, reducing humidity levels at night when fungal spores are most active.
            </p>
          </ion-label>
        </ion-item>

        <!-- Prévention -->
        <ion-item lines="none">
          <ion-label>
            <h2 class="orbitron_bold">Prevention Tips</h2>
            <p class="white">
              Prevention is the most effective strategy to **avoid rust outbreaks**:<br>
              Ensure proper **air circulation** around plants by pruning overcrowded foliage.<br>
              Avoid overhead watering, as wet leaves create ideal conditions for fungal spores.<br>
              Regularly **apply compost or organic mulch** to maintain soil health and improve plant immunity.<br>
              Rotate crops every season to prevent rust fungi from persisting in the soil.<br>
              Monitor plants regularly for early signs of infection and take immediate action if needed.
            </p>
          </ion-label>
        </ion-item>
      </ion-list>
    </ion-card-content>
</ion-card>

        ```

        Return the response strictly following this format.
        """},
        *image_data
    ]}
]

    payload = {
        "model": "gpt-4o",
        "messages": messages,
        "max_tokens": 1500
    }

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
    response.raise_for_status()
    return response.json()['choices'][0]['message']['content']